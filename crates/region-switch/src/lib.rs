//! ARC Region Switch subset: two-region, one-step routing-control plans.
//! The routing-control backend is injected; this crate never owns ARC state.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{Method, StatusCode};
use locallycloud_core::handler::{NativeHandler, ServiceRequest};
use serde_json::{json, Value};
use uuid::Uuid;

/// Implement with ARC's real data-plane operations, preserving its safety rules.
pub trait RoutingControls: Send + Sync {
    fn get(&self, arn: &str) -> Result<bool, String>;
    fn set(&self, arn: &str, on: bool) -> Result<(), String>;
}

/// Verify an existing execution role and authorize its use for each ARC control.
/// Implementations must fail closed when IAM is unavailable. In strict mode this also
/// checks caller PassRole, service trust and the role's scoped ARC policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleAuthorizationPhase {
    PlanCreation,
    Execution,
}

#[async_trait]
pub trait ExecutionRoleAuthorizer: Send + Sync {
    async fn authorize_caller(
        &self,
        request: &ServiceRequest,
        operation: &str,
        resource: &str,
    ) -> Result<(), String>;

    async fn authorize(
        &self,
        request: &ServiceRequest,
        role_arn: &str,
        routing_control_arn: &str,
        phase: RoleAuthorizationPhase,
    ) -> Result<(), String>;
}

#[derive(Clone)]
struct Plan {
    value: Value,
    account: String,
    controls: BTreeMap<String, String>,
    actions: Vec<(String, String, String)>,
}

#[derive(Clone)]
struct Execution {
    value: Value,
    fingerprint: String,
    response: Value,
}

#[derive(Default)]
struct State {
    plans: BTreeMap<String, Plan>,
    executions: BTreeMap<(String, String), Execution>,
    tokens: BTreeMap<(String, String), String>,
}

pub struct RegionSwitchHandler {
    controls: Arc<dyn RoutingControls>,
    roles: Arc<dyn ExecutionRoleAuthorizer>,
    state: Mutex<State>,
}

impl RegionSwitchHandler {
    pub fn new(
        controls: Arc<dyn RoutingControls>,
        roles: Arc<dyn ExecutionRoleAuthorizer>,
    ) -> Self {
        Self {
            controls,
            roles,
            state: Mutex::new(State::default()),
        }
    }

    async fn dispatch(
        &self,
        op: &str,
        request: &ServiceRequest,
        body: &Value,
    ) -> Result<Value, Error> {
        let resource = match op {
            "CreatePlan" => "*",
            "GetPlan" => body.get("arn").and_then(Value::as_str).unwrap_or("*"),
            "StartPlanExecution" | "GetPlanExecution" => {
                body.get("planArn").and_then(Value::as_str).unwrap_or("*")
            }
            _ => return Err(Error::invalid("Unsupported Region Switch operation")),
        };
        self.roles
            .authorize_caller(request, op, resource)
            .await
            .map_err(Error::denied)?;
        match op {
            "CreatePlan" => {
                if body.as_object().is_some_and(|fields| {
                    fields.keys().any(|key| {
                        ![
                            "name",
                            "regions",
                            "executionRole",
                            "recoveryApproach",
                            "primaryRegion",
                            "workflows",
                            "description",
                            "tags",
                            "recoveryTimeObjectiveMinutes",
                        ]
                        .contains(&key.as_str())
                    })
                }) {
                    return Err(Error::invalid("Unsupported plan configuration"));
                }
                let name = required(body, "name")?;
                if name.is_empty()
                    || name.len() > 32
                    || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                {
                    return Err(Error::invalid("Invalid plan name"));
                }
                let regions = body
                    .get("regions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::invalid("regions must contain two Regions"))?;
                if regions.len() != 2
                    || regions[0].as_str().is_none()
                    || regions[1].as_str().is_none()
                    || regions[0] == regions[1]
                {
                    return Err(Error::invalid("regions must contain two distinct Regions"));
                }
                let r0 = regions[0].as_str().unwrap();
                let r1 = regions[1].as_str().unwrap();
                let role = required(body, "executionRole")?;
                if !role.starts_with(&format!("arn:aws:iam::{}:role/", request.account_id)) {
                    return Err(Error::invalid("executionRole must belong to this account"));
                }
                if required(body, "recoveryApproach")? != "activePassive" {
                    return Err(Error::invalid("Only activePassive recovery is supported"));
                }
                let workflows = body
                    .get("workflows")
                    .and_then(Value::as_array)
                    .filter(|w| !w.is_empty())
                    .ok_or_else(|| Error::invalid("workflows required"))?;
                let mut first = None;
                let mut actions = Vec::new();
                for workflow in workflows {
                    let action = required(workflow, "workflowTargetAction")?;
                    if !matches!(action, "activate" | "deactivate") {
                        return Err(Error::invalid(
                            "Only activate/deactivate workflows are supported",
                        ));
                    }
                    let target = required(workflow, "workflowTargetRegion")?;
                    if target != r0 && target != r1 {
                        return Err(Error::invalid("workflowTargetRegion must be in regions"));
                    }
                    let steps = workflow
                        .get("steps")
                        .and_then(Value::as_array)
                        .filter(|s| s.len() == 1)
                        .ok_or_else(|| {
                            Error::invalid("Exactly one ARCRoutingControl step is required")
                        })?;
                    let step = &steps[0];
                    if required(step, "executionBlockType")? != "ARCRoutingControl" {
                        return Err(Error::invalid(
                            "Only ARCRoutingControl execution blocks are supported",
                        ));
                    }
                    let step_name = required(step, "name")?;
                    if actions.iter().any(|(a, r, _)| a == action && r == target) {
                        return Err(Error::invalid(
                            "Duplicate workflow action and target Region",
                        ));
                    }
                    actions.push((
                        action.to_string(),
                        target.to_string(),
                        step_name.to_string(),
                    ));
                    let config = step
                        .get("executionBlockConfiguration")
                        .and_then(Value::as_object)
                        .filter(|c| c.len() == 1)
                        .and_then(|c| c.get("arcRoutingControlConfig"))
                        .ok_or_else(|| Error::invalid("arcRoutingControlConfig required"))?;
                    if config.as_object().is_some_and(|fields| {
                        fields
                            .keys()
                            .any(|key| key != "regionAndRoutingControls" && key != "timeoutMinutes")
                    }) {
                        return Err(Error::invalid(
                            "Cross-account ARC controls are not supported",
                        ));
                    }
                    let controls = config
                        .get("regionAndRoutingControls")
                        .and_then(Value::as_object)
                        .ok_or_else(|| Error::invalid("regionAndRoutingControls required"))?;
                    if controls.len() != 2
                        || !controls.contains_key(r0)
                        || !controls.contains_key(r1)
                    {
                        return Err(Error::invalid(
                            "One routing control is required per plan Region",
                        ));
                    }
                    let mut pair = BTreeMap::new();
                    for region in [r0, r1] {
                        let entries = controls[region]
                            .as_array()
                            .filter(|v| v.len() == 1)
                            .ok_or_else(|| {
                                Error::invalid("One routing control is required per Region")
                            })?;
                        let arn = required(&entries[0], "routingControlArn")?;
                        if !arn.starts_with("arn:aws:route53-recovery-control::")
                            || arn.split(':').nth(3) != Some("")
                            || arn.split(':').nth(4) != Some(request.account_id.as_str())
                            || !arn.split(':').nth(5).is_some_and(|r| {
                                r.starts_with("routingcontrol/") || r.contains("/routingcontrol/")
                            })
                        {
                            return Err(Error::invalid(
                                "routingControlArn must belong to this account",
                            ));
                        }
                        let expected_on = (action == "activate") == (region == target);
                        let expected = if expected_on { "On" } else { "Off" };
                        if required(&entries[0], "state")? != expected {
                            return Err(Error::invalid(
                                "Workflow routing control states do not match target action",
                            ));
                        }
                        pair.insert(region.to_string(), arn.to_string());
                    }
                    if pair[r0] == pair[r1] {
                        return Err(Error::invalid("Regions require distinct routing controls"));
                    }
                    if let Some(previous) = &first {
                        if previous != &pair {
                            return Err(Error::invalid(
                                "Workflows must use the same routing controls",
                            ));
                        }
                    } else {
                        first = Some(pair);
                    }
                }
                let controls: BTreeMap<String, String> = first.unwrap();
                for control in controls.values() {
                    self.roles
                        .authorize(request, role, control, RoleAuthorizationPhase::PlanCreation)
                        .await
                        .map_err(Error::denied)?;
                }
                let mut state = self.state.lock().map_err(|_| Error::internal())?;
                if state
                    .plans
                    .values()
                    .any(|plan| plan.account == request.account_id && plan.value["name"] == name)
                {
                    return Err(Error::conflict("Plan name already exists"));
                }
                let arn = format!(
                    "arn:aws:arc-region-switch::{}:plan/{}:{}",
                    request.account_id,
                    name,
                    &Uuid::new_v4().simple().to_string()[..6]
                );
                let mut value = json!({"arn":arn,"name":name,"owner":request.account_id,"regions":regions,
                    "recoveryApproach":"activePassive","executionRole":role,"workflows":workflows,"version":"1","updatedAt":now()});
                if let Some(primary) = body.get("primaryRegion") {
                    if primary != &regions[0] && primary != &regions[1] {
                        return Err(Error::invalid("primaryRegion must be in regions"));
                    }
                    value["primaryRegion"] = primary.clone();
                }
                if let Some(description) = body.get("description") {
                    value["description"] = description.clone();
                }
                state.plans.insert(
                    arn,
                    Plan {
                        value: value.clone(),
                        account: request.account_id.clone(),
                        controls,
                        actions,
                    },
                );
                Ok(json!({"plan":value}))
            }
            "GetPlan" => {
                let arn = required(body, "arn")?;
                let state = self.state.lock().map_err(|_| Error::internal())?;
                let plan = scoped_plan(&state, arn, &request.account_id)?;
                Ok(json!({"plan":plan.value}))
            }
            "StartPlanExecution" => {
                let arn = required(body, "planArn")?.to_string();
                let plan = {
                    let state = self.state.lock().map_err(|_| Error::internal())?;
                    scoped_plan(&state, &arn, &request.account_id)?.clone()
                };
                let target = required(body, "targetRegion")?;
                let action = required(body, "action")?;
                let step_name = plan
                    .actions
                    .iter()
                    .find(|(a, r, _)| a == action && r == target)
                    .map(|(_, _, name)| name.clone())
                    .ok_or_else(|| {
                        Error::invalid("No workflow for this action and target Region")
                    })?;
                if !plan.controls.contains_key(target) {
                    return Err(Error::invalid("targetRegion is not in plan"));
                }
                let mode = body
                    .get("mode")
                    .and_then(Value::as_str)
                    .unwrap_or("graceful");
                if !matches!(mode, "graceful" | "ungraceful") {
                    return Err(Error::invalid("Invalid execution mode"));
                }
                let token = body
                    .get("clientToken")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                if token.as_ref().is_some_and(|t| {
                    t.is_empty() || t.len() > 128 || !t.bytes().all(|b| (33..=126).contains(&b))
                }) {
                    return Err(Error::invalid("Invalid clientToken"));
                }
                let mut fingerprint = body.clone();
                fingerprint.as_object_mut().unwrap().remove("clientToken");
                let fingerprint = fingerprint.to_string();
                if let Some(token) = &token {
                    let state = self.state.lock().map_err(|_| Error::internal())?;
                    if let Some(id) = state.tokens.get(&(arn.clone(), token.clone())) {
                        let previous = &state.executions[&(arn.clone(), id.clone())];
                        if previous.fingerprint != fingerprint {
                            return Err(Error::conflict(
                                "clientToken already used with different parameters",
                            ));
                        }
                        return Ok(previous.response.clone());
                    }
                }
                for control in plan.controls.values() {
                    self.roles
                        .authorize(
                            request,
                            plan.value["executionRole"].as_str().unwrap(),
                            control,
                            RoleAuthorizationPhase::Execution,
                        )
                        .await
                        .map_err(Error::denied)?;
                }
                let mut state = self.state.lock().map_err(|_| Error::internal())?;
                if let Some(token) = &token {
                    if let Some(id) = state.tokens.get(&(arn.clone(), token.clone())) {
                        let previous = &state.executions[&(arn.clone(), id.clone())];
                        if previous.fingerprint != fingerprint {
                            return Err(Error::conflict(
                                "clientToken already used with different parameters",
                            ));
                        }
                        return Ok(previous.response.clone());
                    }
                }
                let destination = if action == "activate" {
                    target.to_string()
                } else {
                    plan.controls
                        .keys()
                        .find(|r| r.as_str() != target)
                        .unwrap()
                        .clone()
                };
                let origin = plan
                    .controls
                    .keys()
                    .find(|r| *r != &destination)
                    .unwrap()
                    .clone();
                let destination_arn = &plan.controls[&destination];
                let origin_arn = &plan.controls[&origin];
                let id = format!("{}/{}", request.region, Uuid::new_v4().simple());
                let started = now();
                // The destination must be On before the origin can be Off. If the second
                // operation fails, both controls remain On and traffic is never blackholed.
                let result = self
                    .controls
                    .get(origin_arn)
                    .and_then(|_| self.controls.set(destination_arn, true))
                    .and_then(|_| self.controls.get(destination_arn))
                    .and_then(|on| {
                        if on {
                            self.controls.set(origin_arn, false)
                        } else {
                            Err("Destination routing control did not become On".into())
                        }
                    });
                let (execution_state, step_status) = if result.is_ok() {
                    ("completed", "completed")
                } else {
                    ("failed", "failed")
                };
                let mut execution = json!({"planArn":arn,"executionId":id,"version":"1","startTime":started,
                    "endTime":now(),"updatedAt":now(),"mode":mode,"executionState":execution_state,
                    "executionAction":action,"executionRegion":target,"plan":plan.value,
                    "stepStates":[{"name":step_name,"status":step_status,"startTime":started,"endTime":now()}]});
                if let Err(error) = result {
                    execution["comment"] = json!(error);
                }
                let response = json!({"executionId":id,"plan":arn,"planVersion":"1","activateRegion":destination,"deactivateRegion":origin});
                state.executions.insert(
                    (arn.clone(), id.clone()),
                    Execution {
                        value: execution,
                        fingerprint,
                        response: response.clone(),
                    },
                );
                if let Some(token) = token {
                    state.tokens.insert((arn, token), id);
                }
                Ok(response)
            }
            "GetPlanExecution" => {
                let arn = required(body, "planArn")?;
                let state = self.state.lock().map_err(|_| Error::internal())?;
                scoped_plan(&state, arn, &request.account_id)?;
                let id = required(body, "executionId")?;
                let execution = state
                    .executions
                    .get(&(arn.to_string(), id.to_string()))
                    .ok_or_else(|| Error::not_found("Plan execution not found"))?;
                Ok(execution.value.clone())
            }
            _ => Err(Error::invalid("Unsupported Region Switch operation")),
        }
    }
}

fn scoped_plan<'a>(state: &'a State, arn: &str, account: &str) -> Result<&'a Plan, Error> {
    state
        .plans
        .get(arn)
        .filter(|p| p.account == account)
        .ok_or_else(|| Error::not_found("Plan not found"))
}

fn required<'a>(value: &'a Value, field: &str) -> Result<&'a str, Error> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::invalid(format!("{field} is required")))
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Debug)]
struct Error {
    code: &'static str,
    status: StatusCode,
    message: String,
}
impl Error {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "IllegalArgumentException",
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: "ResourceNotFoundException",
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    fn denied(message: impl Into<String>) -> Self {
        Self {
            code: "AccessDeniedException",
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: "ConflictException",
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
    fn internal() -> Self {
        Self {
            code: "InternalServerException",
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Internal error".into(),
        }
    }
    fn response(self) -> Response {
        Response::builder()
            .status(self.status)
            .header("content-type", "application/x-amz-json-1.0")
            .header("x-amzn-errortype", self.code)
            .body(Body::from(
                json!({"__type":self.code,"message":self.message}).to_string(),
            ))
            .unwrap()
    }
}

#[async_trait]
impl NativeHandler for RegionSwitchHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|h| h.to_str().ok());
        let Some(op) = target.and_then(|t| t.strip_prefix("ArcRegionSwitch.")) else {
            return Error::invalid("Invalid X-Amz-Target").response();
        };
        if request.method != Method::POST || request.uri.path() != "/" {
            return Error::invalid("Only POST / is supported").response();
        }
        let body: Value = match serde_json::from_slice::<Value>(&request.body) {
            Ok(value) if value.is_object() => value,
            _ => return Error::invalid("Invalid JSON request").response(),
        };
        match self.dispatch(op, &request, &body).await {
            Ok(value) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-amz-json-1.0")
                .body(Body::from(value.to_string()))
                .unwrap(),
            Err(error) => error.response(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Uri};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct Controls {
        on: Mutex<BTreeMap<String, bool>>,
        calls: Mutex<Vec<(String, bool)>>,
        fail_off: bool,
    }
    impl RoutingControls for Controls {
        fn get(&self, arn: &str) -> Result<bool, String> {
            self.on
                .lock()
                .unwrap()
                .get(arn)
                .copied()
                .ok_or("Unknown control".into())
        }
        fn set(&self, arn: &str, on: bool) -> Result<(), String> {
            if !on && self.fail_off {
                return Err("ARC denied origin Off".into());
            }
            self.on.lock().unwrap().insert(arn.into(), on);
            self.calls.lock().unwrap().push((arn.into(), on));
            Ok(())
        }
    }
    struct Roles {
        exists: AtomicBool,
        caller_allowed: AtomicBool,
    }
    #[async_trait]
    impl ExecutionRoleAuthorizer for Roles {
        async fn authorize_caller(
            &self,
            _: &ServiceRequest,
            _: &str,
            _: &str,
        ) -> Result<(), String> {
            if self.caller_allowed.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("Caller is not authorized".into())
            }
        }

        async fn authorize(
            &self,
            _: &ServiceRequest,
            role: &str,
            _: &str,
            _: RoleAuthorizationPhase,
        ) -> Result<(), String> {
            if self.exists.load(Ordering::SeqCst) && role == "arn:aws:iam::123456789012:role/switch"
            {
                Ok(())
            } else {
                Err("Execution role unavailable".into())
            }
        }
    }
    fn request() -> ServiceRequest {
        ServiceRequest {
            method: Method::POST,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            body: Default::default(),
            region: "us-east-1".into(),
            account_id: "123456789012".into(),
            request_id: "test".into(),
        }
    }
    fn plan() -> Value {
        let east = "arn:aws:route53-recovery-control::123456789012:routingcontrol/east";
        let west = "arn:aws:route53-recovery-control::123456789012:routingcontrol/west";
        json!({"name":"switch","regions":["us-east-1","us-west-2"],
            "executionRole":"arn:aws:iam::123456789012:role/switch",
            "recoveryApproach":"activePassive","primaryRegion":"us-east-1",
            "workflows":[{"workflowTargetAction":"activate","workflowTargetRegion":"us-west-2",
                "steps":[{"name":"shift","executionBlockType":"ARCRoutingControl",
                    "executionBlockConfiguration":{"arcRoutingControlConfig":{"regionAndRoutingControls":{
                        "us-east-1":[{"routingControlArn":east,"state":"Off"}],
                        "us-west-2":[{"routingControlArn":west,"state":"On"}]}}}}]}]})
    }
    #[tokio::test]
    async fn switches_destination_first_and_replays_token() {
        let backend = Arc::new(Controls::default());
        let roles = Arc::new(Roles {
            exists: AtomicBool::new(true),
            caller_allowed: AtomicBool::new(true),
        });
        let east = "arn:aws:route53-recovery-control::123456789012:routingcontrol/east";
        let west = "arn:aws:route53-recovery-control::123456789012:routingcontrol/west";
        backend.on.lock().unwrap().insert(east.into(), true);
        backend.on.lock().unwrap().insert(west.into(), false);
        let handler = RegionSwitchHandler::new(backend.clone(), roles.clone());
        let created = handler
            .dispatch("CreatePlan", &request(), &plan())
            .await
            .unwrap();
        let arn = created["plan"]["arn"].as_str().unwrap();
        let start = json!({"planArn":arn,"targetRegion":"us-west-2","action":"activate","clientToken":"retry-1"});
        roles.caller_allowed.store(false, Ordering::SeqCst);
        assert_eq!(
            handler
                .dispatch("StartPlanExecution", &request(), &start)
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        assert!(backend.calls.lock().unwrap().is_empty());
        roles.caller_allowed.store(true, Ordering::SeqCst);
        let first = handler
            .dispatch("StartPlanExecution", &request(), &start)
            .await
            .unwrap();
        assert_eq!(
            handler
                .dispatch("StartPlanExecution", &request(), &start)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            &[(west.into(), true), (east.into(), false)]
        );
        let got = handler
            .dispatch(
                "GetPlanExecution",
                &request(),
                &json!({"planArn":arn,"executionId":first["executionId"]}),
            )
            .await
            .unwrap();
        assert_eq!(got["executionState"], "completed");
        assert_eq!(got["stepStates"][0]["name"], "shift");
        let mismatch = json!({"planArn":arn,"targetRegion":"us-west-2","action":"activate","clientToken":"retry-1","comment":"changed"});
        assert_eq!(
            handler
                .dispatch("StartPlanExecution", &request(), &mismatch)
                .await
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        roles.exists.store(false, Ordering::SeqCst);
        assert_eq!(
            handler
                .dispatch("StartPlanExecution", &request(), &start)
                .await
                .unwrap(),
            first
        );
        assert_eq!(
            handler
                .dispatch(
                    "StartPlanExecution",
                    &request(),
                    &json!({"planArn":arn,"targetRegion":"us-west-2","action":"activate"})
                )
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn denies_missing_role_and_cross_account_control() {
        let backend = Arc::new(Controls::default());
        let roles = Arc::new(Roles {
            exists: AtomicBool::new(true),
            caller_allowed: AtomicBool::new(true),
        });
        let handler = RegionSwitchHandler::new(backend.clone(), roles.clone());
        let mut invalid = plan();
        invalid["executionRole"] = json!("arn:aws:iam::123456789012:role/imaginary");
        assert_eq!(
            handler
                .dispatch("CreatePlan", &request(), &invalid)
                .await
                .unwrap_err()
                .status,
            StatusCode::FORBIDDEN
        );
        invalid = plan();
        invalid["workflows"][0]["steps"][0]["executionBlockConfiguration"]
            ["arcRoutingControlConfig"]["regionAndRoutingControls"]["us-west-2"][0]
            ["routingControlArn"] =
            json!("arn:aws:route53-recovery-control::999999999999:routingcontrol/west");
        assert_eq!(
            handler
                .dispatch("CreatePlan", &request(), &invalid)
                .await
                .unwrap_err()
                .status,
            StatusCode::BAD_REQUEST
        );
        assert!(backend.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn failed_arc_step_keeps_both_controls_on() {
        let backend = Arc::new(Controls {
            fail_off: true,
            ..Controls::default()
        });
        let east = "arn:aws:route53-recovery-control::123456789012:routingcontrol/east";
        let west = "arn:aws:route53-recovery-control::123456789012:routingcontrol/west";
        backend.on.lock().unwrap().insert(east.into(), true);
        backend.on.lock().unwrap().insert(west.into(), false);
        let handler = RegionSwitchHandler::new(
            backend.clone(),
            Arc::new(Roles {
                exists: AtomicBool::new(true),
                caller_allowed: AtomicBool::new(true),
            }),
        );
        let created = handler
            .dispatch("CreatePlan", &request(), &plan())
            .await
            .unwrap();
        let arn = created["plan"]["arn"].as_str().unwrap();
        let started = handler
            .dispatch(
                "StartPlanExecution",
                &request(),
                &json!({"planArn":arn,"targetRegion":"us-west-2","action":"activate"}),
            )
            .await
            .unwrap();
        let got = handler
            .dispatch(
                "GetPlanExecution",
                &request(),
                &json!({"planArn":arn,"executionId":started["executionId"]}),
            )
            .await
            .unwrap();
        assert_eq!(got["executionState"], "failed");
        assert!(backend.get(east).unwrap());
        assert!(backend.get(west).unwrap());
    }
}
