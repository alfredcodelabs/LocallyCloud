//! Scheduler resources use the existing scoped REST dispatcher.
use super::*;

const PROPERTIES: &[&str] = &[
    "Name",
    "GroupName",
    "Description",
    "ScheduleExpression",
    "ScheduleExpressionTimezone",
    "StartDate",
    "EndDate",
    "FlexibleTimeWindow",
    "State",
    "Target",
];

fn body(logical: &str, props: &Value) -> Result<Value, CfnError> {
    ensure_known_properties(logical, "AWS::Scheduler::Schedule", props, PROPERTIES)?;
    required_property(props, "ScheduleExpression", logical)?;
    for field in ["FlexibleTimeWindow", "Target"] {
        if !props.get(field).is_some_and(Value::is_object) {
            return Err(CfnError::Validation(format!(
                "Scheduler {logical} requires object {field}"
            )));
        }
    }
    let mut body = props.clone();
    body.as_object_mut()
        .ok_or_else(|| CfnError::Validation("Scheduler Properties must be an object".into()))?
        .remove("Name");
    Ok(body)
}
fn resolution(response: &Value, name: &str, logical: &str) -> Result<ResolvedResource, CfnError> {
    let arn = required_response_string(response, "ScheduleArn", logical)?;
    Ok(ResolvedResource {
        ref_value: name.into(),
        attributes: [("Arn".into(), arn)].into(),
    })
}
fn group(props: &Value) -> &str {
    props
        .get("GroupName")
        .and_then(Value::as_str)
        .unwrap_or("default")
}
impl Provisioner {
    pub(super) async fn scheduler_schedule(
        &self,
        logical: &str,
        stack: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = props
            .get("Name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| generate_name(stack, logical, 64));
        let response = self
            .call_json(
                "scheduler",
                Method::POST,
                &format!("/schedules/{}", enc(&name)),
                body(logical, props)?,
                logical,
            )
            .await?;
        match resolution(&response, &name, logical) {
            Ok(resource) => Ok(resource),
            Err(error) => match self.delete_scheduler_schedule(&name, props).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(with_cleanup_failure(error, cleanup)),
            },
        }
    }
    pub(super) async fn update_scheduler_schedule(
        &self,
        logical: &str,
        name: &str,
        old: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if old.get("Name") != props.get("Name") {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::Scheduler::Schedule Name requires replacement for {logical}"
            )));
        }
        let payload = body(logical, props)?;
        let changed_group = group(old) != group(props);
        let response = self
            .call_json(
                "scheduler",
                if changed_group {
                    Method::POST
                } else {
                    Method::PUT
                },
                &format!("/schedules/{}", enc(name)),
                payload,
                logical,
            )
            .await?;
        let result = match resolution(&response, name, logical) {
            Ok(result) => result,
            Err(error) if changed_group => {
                return match self.delete_scheduler_schedule(name, props).await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(with_cleanup_failure(error, cleanup)),
                };
            }
            Err(error) => return Err(error),
        };
        if changed_group {
            if let Err(error) = self.delete_scheduler_schedule(name, old).await {
                return match self.delete_scheduler_schedule(name, props).await {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(with_cleanup_failure(error, cleanup)),
                };
            }
        }
        Ok(result)
    }
    pub(super) async fn delete_scheduler_schedule(
        &self,
        name: &str,
        props: &Value,
    ) -> Result<(), CfnError> {
        let (status, response) = self
            .call(
                "scheduler",
                Method::DELETE,
                &format!("/schedules/{}?groupName={}", enc(name), enc(group(props))),
                json_host(),
                Bytes::new(),
            )
            .await?;
        if (200..300).contains(&status) || status == 404 {
            return Ok(());
        }
        Err(CfnError::ResourceFailed(format!(
            "Scheduler deletion failed ({status}): {}",
            String::from_utf8_lossy(&response)
        )))
    }
}
