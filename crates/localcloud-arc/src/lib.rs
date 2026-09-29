//! Amazon ARC routing controls. Configuration and cluster calls share one in-memory state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use http::{header, Method, StatusCode};
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use serde_json::{json, Value};
use uuid::Uuid;

const CONFIG: &str = "route53-recovery-control-config";
const CLUSTER: &str = "route53-recovery-cluster";
const REGIONS: [&str; 5] = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "ap-northeast-1",
    "ap-southeast-2",
];

#[derive(Default)]
struct State {
    clusters: BTreeMap<String, Cluster>,
    panels: BTreeMap<String, Panel>,
    controls: BTreeMap<String, Control>,
    rules: BTreeMap<String, Rule>,
}

struct Cluster {
    account: String,
    name: String,
    arn: String,
    default_panel: String,
}

struct Panel {
    account: String,
    cluster: String,
    name: String,
    arn: String,
    is_default: bool,
}

struct Control {
    account: String,
    panel: String,
    name: String,
    arn: String,
    on: bool,
}

struct Rule {
    account: String,
    panel: String,
    name: String,
    arn: String,
    asserted: Vec<String>,
}

/// Clonable handle for Route 53 ARC health checks.
#[derive(Default)]
pub struct ArcService {
    state: Mutex<State>,
}

impl ArcService {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Apply an internal state update with the same account and safety checks as the AWS API.
    pub fn set_state(&self, routing_control_arn: &str, on: bool) -> Result<(), String> {
        let account = routing_control_arn
            .split(':')
            .nth(4)
            .ok_or("Invalid routing control ARN")?;
        let mut state = self.state.lock().map_err(|_| "ARC state is unavailable")?;
        update(&mut state, account, &[(routing_control_arn.to_owned(), on)])
            .map_err(|error| error.message)
    }

    /// Returns `None` for an unknown routing control. Route 53 should treat that as unhealthy.
    pub fn is_on(&self, routing_control_arn: &str) -> Option<bool> {
        self.state
            .lock()
            .ok()?
            .controls
            .get(routing_control_arn)
            .map(|c| c.on)
    }

    fn handle_config(&self, request: ServiceRequest) -> Result<Value, Error> {
        let path = request.uri.path();
        let method = &request.method;
        let body = parse_body(&request)?;
        let mut state = self.state.lock().map_err(|_| Error::internal())?;
        let account = request.account_id.as_str();
        match (method, path) {
            (&Method::POST, "/cluster") => {
                let name = required(&body, "ClusterName")?;
                valid_name(name)?;
                if state
                    .clusters
                    .values()
                    .any(|c| c.account == account && c.name == name)
                {
                    return Err(Error::conflict("Cluster name already exists"));
                }
                let id = Uuid::new_v4().to_string();
                let arn = format!("arn:aws:route53-recovery-control::{account}:cluster/{id}");
                let panel = format!(
                    "arn:aws:route53-recovery-control::{account}:controlpanel/{}",
                    Uuid::new_v4().simple()
                );
                state.panels.insert(
                    panel.clone(),
                    Panel {
                        account: account.into(),
                        cluster: arn.clone(),
                        name: "DefaultControlPanel".into(),
                        arn: panel.clone(),
                        is_default: true,
                    },
                );
                state.clusters.insert(
                    arn.clone(),
                    Cluster {
                        account: account.into(),
                        name: name.into(),
                        arn: arn.clone(),
                        default_panel: panel,
                    },
                );
                Ok(json!({"Cluster": cluster_json(state.clusters.get(&arn).unwrap())}))
            }
            (&Method::GET, "/cluster") => Ok(
                json!({"Clusters": state.clusters.values().filter(|c| c.account == account).map(cluster_json).collect::<Vec<_>>() }),
            ),
            (&Method::POST, "/controlpanel") => {
                let cluster = required(&body, "ClusterArn")?;
                let name = required(&body, "ControlPanelName")?;
                valid_name(name)?;
                if !state
                    .clusters
                    .get(cluster)
                    .is_some_and(|c| c.account == account)
                {
                    return Err(Error::not_found());
                }
                if state
                    .panels
                    .values()
                    .any(|p| p.cluster == cluster && p.name == name)
                {
                    return Err(Error::conflict("Control panel name already exists"));
                }
                let arn = format!(
                    "arn:aws:route53-recovery-control::{account}:controlpanel/{}",
                    Uuid::new_v4().simple()
                );
                state.panels.insert(
                    arn.clone(),
                    Panel {
                        account: account.into(),
                        cluster: cluster.into(),
                        name: name.into(),
                        arn: arn.clone(),
                        is_default: false,
                    },
                );
                Ok(json!({"ControlPanel": panel_json(state.panels.get(&arn).unwrap(), &state)}))
            }
            (&Method::POST, "/routingcontrol") => {
                let cluster = required(&body, "ClusterArn")?;
                let name = required(&body, "RoutingControlName")?;
                valid_name(name)?;
                let default_panel = state
                    .clusters
                    .get(cluster)
                    .filter(|c| c.account == account)
                    .ok_or_else(Error::not_found)?
                    .default_panel
                    .clone();
                let panel = body
                    .get("ControlPanelArn")
                    .and_then(Value::as_str)
                    .unwrap_or(&default_panel);
                if !state
                    .panels
                    .get(panel)
                    .is_some_and(|p| p.account == account && p.cluster == cluster)
                {
                    return Err(Error::not_found());
                }
                if state
                    .controls
                    .values()
                    .any(|c| c.panel == panel && c.name == name)
                {
                    return Err(Error::conflict("Routing control name already exists"));
                }
                let arn = format!("{panel}/routingcontrol/{}", Uuid::new_v4().simple());
                state.controls.insert(
                    arn.clone(),
                    Control {
                        account: account.into(),
                        panel: panel.into(),
                        name: name.into(),
                        arn: arn.clone(),
                        on: false,
                    },
                );
                Ok(json!({"RoutingControl": control_json(state.controls.get(&arn).unwrap())}))
            }
            (&Method::POST, "/safetyrule") => {
                if body.get("GatingRule").is_some() {
                    return Err(Error::invalid("Gating rules are not supported"));
                }
                let rule = body
                    .get("AssertionRule")
                    .ok_or_else(|| Error::invalid("AssertionRule is required"))?;
                let panel = required(rule, "ControlPanelArn")?;
                let name = required(rule, "Name")?;
                valid_name(name)?;
                if !state
                    .panels
                    .get(panel)
                    .is_some_and(|p| p.account == account)
                {
                    return Err(Error::not_found());
                }
                let config = rule
                    .get("RuleConfig")
                    .ok_or_else(|| Error::invalid("RuleConfig is required"))?;
                if config.get("Type").and_then(Value::as_str) != Some("ATLEAST")
                    || config.get("Threshold").and_then(Value::as_u64) != Some(1)
                    || config
                        .get("Inverted")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                {
                    return Err(Error::invalid(
                        "Only ATLEAST 1 assertion rules are supported",
                    ));
                }
                let asserted = rule
                    .get("AssertedControls")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::invalid("AssertedControls is required"))?
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| Error::invalid("Invalid asserted control"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if asserted.len() < 2
                    || asserted.iter().collect::<BTreeSet<_>>().len() != asserted.len()
                    || asserted.iter().any(|arn| {
                        !state
                            .controls
                            .get(arn)
                            .is_some_and(|c| c.panel == panel && c.account == account)
                    })
                {
                    return Err(Error::invalid(
                        "Asserted controls must be distinct controls in the panel",
                    ));
                }
                if state
                    .rules
                    .values()
                    .any(|r| r.panel == panel && r.name == name)
                {
                    return Err(Error::conflict("Safety rule name already exists"));
                }
                let arn = format!("{panel}/safetyrule/{}", Uuid::new_v4().simple());
                state.rules.insert(
                    arn.clone(),
                    Rule {
                        account: account.into(),
                        panel: panel.into(),
                        name: name.into(),
                        arn: arn.clone(),
                        asserted,
                    },
                );
                Ok(json!({"AssertionRule": rule_json(state.rules.get(&arn).unwrap())}))
            }
            _ => {
                if method == Method::GET {
                    if let Some(arn) = path.strip_prefix("/cluster/") {
                        return state
                            .clusters
                            .get(&decode_arn(arn))
                            .filter(|c| c.account == account)
                            .map(|c| json!({"Cluster": cluster_json(c)}))
                            .ok_or_else(Error::not_found);
                    }
                    if let Some(arn) = path.strip_prefix("/controlpanel/") {
                        return state
                            .panels
                            .get(&decode_arn(arn))
                            .filter(|p| p.account == account)
                            .map(|p| json!({"ControlPanel": panel_json(p, &state)}))
                            .ok_or_else(Error::not_found);
                    }
                    if let Some(arn) = path.strip_prefix("/routingcontrol/") {
                        return state
                            .controls
                            .get(&decode_arn(arn))
                            .filter(|c| c.account == account)
                            .map(|c| json!({"RoutingControl": control_json(c)}))
                            .ok_or_else(Error::not_found);
                    }
                }
                Err(Error::invalid("Unsupported ARC configuration operation"))
            }
        }
    }

    fn handle_cluster(&self, request: ServiceRequest) -> Result<Value, Error> {
        if request.method != Method::POST || request.uri.path() != "/" {
            return Err(Error::invalid("Unsupported ARC cluster operation"));
        }
        let target = request
            .headers
            .get("x-amz-target")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("ToggleCustomerAPI."))
            .ok_or_else(|| Error::invalid("Invalid X-Amz-Target"))?;
        let body = parse_body(&request)?;
        let mut state = self.state.lock().map_err(|_| Error::internal())?;
        let account = request.account_id.as_str();
        match target {
            "GetRoutingControlState" => {
                let arn = required(&body, "RoutingControlArn")?;
                let control = state
                    .controls
                    .get(arn)
                    .filter(|c| c.account == account)
                    .ok_or_else(Error::not_found)?;
                Ok(
                    json!({"RoutingControlArn": control.arn, "RoutingControlName": control.name, "RoutingControlState": if control.on { "On" } else { "Off" }}),
                )
            }
            "UpdateRoutingControlState" => {
                let arn = required(&body, "RoutingControlArn")?;
                let on = parse_state(required(&body, "RoutingControlState")?)?;
                update(&mut state, account, &[(arn.to_owned(), on)])?;
                Ok(json!({}))
            }
            "UpdateRoutingControlStates" => {
                let entries = body
                    .get("UpdateRoutingControlStateEntries")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        Error::invalid("UpdateRoutingControlStateEntries is required")
                    })?;
                if entries.is_empty() || entries.len() > 10 {
                    return Err(Error::invalid("Expected 1 to 10 routing control updates"));
                }
                let updates = entries
                    .iter()
                    .map(|entry| {
                        Ok((
                            required(entry, "RoutingControlArn")?.to_owned(),
                            parse_state(required(entry, "RoutingControlState")?)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, Error>>()?;
                update(&mut state, account, &updates)?;
                Ok(json!({}))
            }
            _ => Err(Error::invalid("Unsupported ARC cluster operation")),
        }
    }
}

fn update(state: &mut State, account: &str, updates: &[(String, bool)]) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for (arn, _) in updates {
        if !seen.insert(arn) {
            return Err(Error::invalid("Duplicate routing control update"));
        }
        if !state
            .controls
            .get(arn)
            .is_some_and(|c| c.account == account)
        {
            return Err(Error::not_found());
        }
    }
    // Evaluate the proposed transaction before changing any state.
    for rule in state
        .rules
        .values()
        .filter(|r| r.account == account && r.asserted.iter().any(|arn| seen.contains(arn)))
    {
        let on = rule.asserted.iter().any(|arn| {
            updates
                .iter()
                .find(|(key, _)| key == arn)
                .map(|(_, value)| *value)
                .unwrap_or_else(|| state.controls.get(arn).is_some_and(|c| c.on))
        });
        if !on {
            return Err(Error::conflict(
                "Safety assertion requires at least one routing control On",
            ));
        }
    }
    for (arn, on) in updates {
        state.controls.get_mut(arn).unwrap().on = *on;
    }
    Ok(())
}

fn decode_arn(path: &str) -> String {
    path.replace("%3A", ":")
        .replace("%3a", ":")
        .replace("%2F", "/")
        .replace("%2f", "/")
}

fn parse_state(value: &str) -> Result<bool, Error> {
    match value {
        "On" => Ok(true),
        "Off" => Ok(false),
        _ => Err(Error::invalid("RoutingControlState must be On or Off")),
    }
}

fn parse_body(request: &ServiceRequest) -> Result<Value, Error> {
    if request.body.len() > 128 * 1024 {
        return Err(Error::invalid("Request body is too large"));
    }
    if request.body.is_empty() {
        Ok(json!({}))
    } else {
        let value: Value = serde_json::from_slice(&request.body)
            .map_err(|_| Error::invalid("Invalid JSON request"))?;
        if !value.is_object() {
            return Err(Error::invalid("JSON object is required"));
        }
        Ok(value)
    }
}

fn required<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::invalid(format!("{key} is required")))
}

fn valid_name(name: &str) -> Result<(), Error> {
    if name.len() > 64 || !name.is_ascii() || name.chars().any(char::is_whitespace) {
        return Err(Error::invalid("Invalid resource name"));
    }
    Ok(())
}

fn cluster_json(c: &Cluster) -> Value {
    json!({"ClusterArn": c.arn, "Name": c.name, "Status": "DEPLOYED", "Owner": c.account, "NetworkType": "IPV4", "ClusterEndpoints": REGIONS.iter().map(|region| json!({"Region": region, "Endpoint": format!("https://{}.route53-recovery-cluster.{region}.amazonaws.com", c.arn.rsplit('/').next().unwrap_or(""))})).collect::<Vec<_>>()})
}

fn panel_json(p: &Panel, state: &State) -> Value {
    json!({"ControlPanelArn": p.arn, "ClusterArn": p.cluster, "Name": p.name, "Status": "DEPLOYED", "DefaultControlPanel": p.is_default, "RoutingControlCount": state.controls.values().filter(|c| c.panel == p.arn).count(), "Owner": p.account})
}

fn control_json(c: &Control) -> Value {
    json!({"RoutingControlArn": c.arn, "ControlPanelArn": c.panel, "Name": c.name, "Status": "DEPLOYED", "Owner": c.account})
}

fn rule_json(r: &Rule) -> Value {
    json!({"SafetyRuleArn": r.arn, "ControlPanelArn": r.panel, "Name": r.name, "Status": "DEPLOYED", "Owner": r.account, "AssertedControls": r.asserted, "RuleConfig": {"Type": "ATLEAST", "Threshold": 1, "Inverted": false}, "WaitPeriodMs": 0})
}

#[derive(Debug)]
struct Error {
    kind: &'static str,
    status: StatusCode,
    message: String,
}
impl Error {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: "ValidationException",
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: "ConflictException",
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn not_found() -> Self {
        Self {
            kind: "ResourceNotFoundException",
            status: StatusCode::BAD_REQUEST,
            message: "ARC resource not found".into(),
        }
    }
    fn internal() -> Self {
        Self {
            kind: "InternalServerException",
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "ARC state is unavailable".into(),
        }
    }
}

fn response(result: Result<Value, Error>, config: bool) -> Response {
    match result {
        Ok(value) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        Err(err) => {
            let body = if config {
                json!({"message": err.message})
            } else {
                json!({"__type": err.kind, "message": err.message})
            };
            Response::builder()
                .status(err.status)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-amzn-errortype", err.kind)
                .body(Body::from(body.to_string()))
                .unwrap()
        }
    }
}

struct Handler {
    service: Arc<ArcService>,
    config: bool,
}
#[async_trait]
impl NativeHandler for Handler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        response(
            if self.config {
                self.service.handle_config(request)
            } else {
                self.service.handle_cluster(request)
            },
            self.config,
        )
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<ArcService> {
    let service = ArcService::new();
    registry.register_native(
        ServiceName::new(CONFIG),
        ServiceMetadata::new(AwsProtocol::RestJson, None),
        Arc::new(Handler {
            service: service.clone(),
            config: true,
        }),
    );
    registry.register_native(
        ServiceName::new(CLUSTER),
        ServiceMetadata::new(AwsProtocol::Json10, Some("ToggleCustomerAPI")),
        Arc::new(Handler {
            service: service.clone(),
            config: false,
        }),
    );
    service
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Uri};

    fn req(
        account: &str,
        method: Method,
        path: &str,
        body: Value,
        target: Option<&str>,
    ) -> ServiceRequest {
        let mut headers = HeaderMap::new();
        if let Some(target) = target {
            headers.insert("x-amz-target", target.parse().unwrap());
        }
        ServiceRequest {
            method,
            uri: path.parse::<Uri>().unwrap(),
            headers,
            body: body.to_string().into(),
            region: "us-west-2".into(),
            account_id: account.into(),
            request_id: "test".into(),
        }
    }

    #[test]
    fn switching_respects_assertion_and_batch_is_atomic() {
        let arc = ArcService::new();
        let account = "111111111111";
        let cluster = arc
            .handle_config(req(
                account,
                Method::POST,
                "/cluster",
                json!({"ClusterName":"app"}),
                None,
            ))
            .unwrap()["Cluster"]["ClusterArn"]
            .as_str()
            .unwrap()
            .to_owned();
        let panel = arc
            .handle_config(req(
                account,
                Method::POST,
                "/controlpanel",
                json!({"ClusterArn":cluster,"ControlPanelName":"prod"}),
                None,
            ))
            .unwrap()["ControlPanel"]["ControlPanelArn"]
            .as_str()
            .unwrap()
            .to_owned();
        let a = arc
            .handle_config(req(
                account,
                Method::POST,
                "/routingcontrol",
                json!({"ClusterArn":cluster,"ControlPanelArn":panel,"RoutingControlName":"east"}),
                None,
            ))
            .unwrap()["RoutingControl"]["RoutingControlArn"]
            .as_str()
            .unwrap()
            .to_owned();
        let b = arc
            .handle_config(req(
                account,
                Method::POST,
                "/routingcontrol",
                json!({"ClusterArn":cluster,"ControlPanelArn":panel,"RoutingControlName":"west"}),
                None,
            ))
            .unwrap()["RoutingControl"]["RoutingControlArn"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(arc.is_on(&a), Some(false));
        arc.handle_config(req(account, Method::POST, "/safetyrule", json!({"AssertionRule":{"ControlPanelArn":panel,"Name":"one-open","AssertedControls":[a,b],"RuleConfig":{"Type":"ATLEAST","Threshold":1,"Inverted":false},"WaitPeriodMs":0}}), None)).unwrap();
        let set = |entries: Value| {
            arc.handle_cluster(req(
                account,
                Method::POST,
                "/",
                json!({"UpdateRoutingControlStateEntries":entries}),
                Some("ToggleCustomerAPI.UpdateRoutingControlStates"),
            ))
        };
        set(json!([{"RoutingControlArn":a,"RoutingControlState":"On"}])).unwrap();
        assert!(set(json!([{"RoutingControlArn":a,"RoutingControlState":"Off"}])).is_err());
        assert_eq!(arc.is_on(&a), Some(true));
        set(json!([{"RoutingControlArn":a,"RoutingControlState":"Off"},{"RoutingControlArn":b,"RoutingControlState":"On"}])).unwrap();
        assert_eq!((arc.is_on(&a), arc.is_on(&b)), (Some(false), Some(true)));
        assert!(set(json!([{"RoutingControlArn":a,"RoutingControlState":"Off"},{"RoutingControlArn":b,"RoutingControlState":"Off"}])).is_err());
        assert_eq!(arc.is_on(&b), Some(true));
        assert!(arc
            .handle_cluster(req(
                "222222222222",
                Method::POST,
                "/",
                json!({"RoutingControlArn":b}),
                Some("ToggleCustomerAPI.GetRoutingControlState")
            ))
            .is_err());
    }
}
