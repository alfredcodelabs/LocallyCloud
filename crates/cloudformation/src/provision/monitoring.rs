//! Basic metric alarms use the same scoped Query dispatch as ordinary AWS calls.
use super::*;

const PROPERTIES: &[&str] = &[
    "AlarmName",
    "AlarmDescription",
    "Namespace",
    "MetricName",
    "Dimensions",
    "Statistic",
    "Unit",
    "Period",
    "EvaluationPeriods",
    "DatapointsToAlarm",
    "Threshold",
    "ComparisonOperator",
    "TreatMissingData",
    "ActionsEnabled",
    "AlarmActions",
    "OKActions",
    "InsufficientDataActions",
];

fn alarm_form(logical: &str, name: &str, props: &Value) -> Result<String, CfnError> {
    ensure_known_properties(logical, "AWS::CloudWatch::Alarm", props, PROPERTIES)?;
    for key in ["Namespace", "MetricName", "Statistic", "ComparisonOperator"] {
        required_property(props, key, logical)?;
    }
    for key in ["Period", "EvaluationPeriods", "Threshold"] {
        if !props.get(key).is_some_and(Value::is_number) {
            return Err(CfnError::Validation(format!(
                "Alarm {logical} requires numeric {key}"
            )));
        }
    }
    if name.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
        return Err(CfnError::Validation(format!(
            "Alarm {logical} requires a valid AlarmName"
        )));
    }
    let mut form = format!(
        "Action=PutMetricAlarm&Version=2010-08-01&AlarmName={}",
        enc(name)
    );
    for (key, value) in props.as_object().ok_or(CfnError::Internal)? {
        match key.as_str() {
            "AlarmName" => {}
            "Dimensions" => {
                let dimensions = value.as_array().ok_or_else(|| {
                    CfnError::Validation("Alarm Dimensions must be an array".into())
                })?;
                for (index, dimension) in dimensions.iter().enumerate() {
                    ensure_known_properties(
                        logical,
                        "AWS::CloudWatch::Alarm.Dimension",
                        dimension,
                        &["Name", "Value"],
                    )?;
                    for key in ["Name", "Value"] {
                        let value = required_property(dimension, key, logical)?;
                        form.push_str(&format!(
                            "&Dimensions.member.{}.{key}={}",
                            index + 1,
                            enc(&value)
                        ));
                    }
                }
            }
            "AlarmActions" | "OKActions" | "InsufficientDataActions" => {
                let actions = value
                    .as_array()
                    .ok_or_else(|| CfnError::Validation(format!("Alarm {key} must be an array")))?;
                for (index, value) in actions.iter().enumerate() {
                    let value = value.as_str().ok_or_else(|| {
                        CfnError::Validation(format!("Alarm {key} entries must be strings"))
                    })?;
                    form.push_str(&format!("&{key}.member.{}={}", index + 1, enc(value)));
                }
            }
            "ActionsEnabled" => {
                let value = value.as_bool().ok_or_else(|| {
                    CfnError::Validation("Alarm ActionsEnabled must be boolean".into())
                })?;
                form.push_str(&format!("&{key}={value}"));
            }
            "Period" | "EvaluationPeriods" | "DatapointsToAlarm" => {
                let value = value.as_u64().ok_or_else(|| {
                    CfnError::Validation(format!("Alarm {key} must be a non-negative integer"))
                })?;
                form.push_str(&format!("&{key}={value}"));
            }
            "Threshold" => {
                let value = value.as_f64().ok_or_else(|| {
                    CfnError::Validation("Alarm Threshold must be numeric".into())
                })?;
                form.push_str(&format!("&{key}={value}"));
            }
            _ => {
                let value = value
                    .as_str()
                    .ok_or_else(|| CfnError::Validation(format!("Alarm {key} must be a string")))?;
                form.push_str(&format!("&{key}={}", enc(value)));
            }
        }
    }
    Ok(form)
}

impl Provisioner {
    async fn alarm_call(
        &self,
        logical: &str,
        action: &str,
        form: String,
    ) -> Result<Bytes, CfnError> {
        let (status, body) = self
            .call(
                "monitoring",
                Method::POST,
                "/",
                form_host(),
                Bytes::from(form),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(CfnError::ResourceFailed(format!(
                "CloudWatch {action} for {logical} failed ({status}): {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(body)
    }
    fn alarm_resolution(&self, name: &str) -> ResolvedResource {
        ResolvedResource {
            ref_value: name.into(),
            attributes: [(
                "Arn".into(),
                format!(
                    "arn:aws:cloudwatch:{}:{}:alarm:{name}",
                    self.region, self.account
                ),
            )]
            .into(),
        }
    }
    pub(super) async fn monitoring_alarm(
        &self,
        logical: &str,
        stack: &str,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        let name = match props.get("AlarmName") {
            Some(value) => value
                .as_str()
                .ok_or_else(|| CfnError::Validation("AlarmName must be a string".into()))?
                .to_owned(),
            None => generate_name(stack, logical, 255),
        };
        let form = alarm_form(logical, &name, props)?;
        let existing = self
            .alarm_call(
                logical,
                "DescribeAlarms",
                format!(
                    "Action=DescribeAlarms&Version=2010-08-01&AlarmNames.member.1={}",
                    enc(&name)
                ),
            )
            .await?;
        if String::from_utf8_lossy(&existing)
            .contains(&format!("<AlarmName>{}</AlarmName>", xml_escape(&name)))
        {
            return Err(CfnError::ResourceFailed(format!(
                "CloudWatch alarm {name} already exists"
            )));
        }
        self.alarm_call(logical, "PutMetricAlarm", form).await?;
        Ok(self.alarm_resolution(&name))
    }
    pub(super) async fn update_monitoring_alarm(
        &self,
        logical: &str,
        current: &ResolvedResource,
        previous: &Value,
        props: &Value,
    ) -> Result<ResolvedResource, CfnError> {
        if previous.get("AlarmName") != props.get("AlarmName") {
            return Err(CfnError::ResourceFailed(format!(
                "AWS::CloudWatch::Alarm AlarmName requires replacement for {logical}"
            )));
        }
        self.alarm_call(
            logical,
            "PutMetricAlarm",
            alarm_form(logical, &current.ref_value, props)?,
        )
        .await?;
        Ok(self.alarm_resolution(&current.ref_value))
    }
    pub(super) async fn delete_monitoring_alarm(&self, name: &str) -> Result<(), CfnError> {
        self.alarm_call(
            name,
            "DeleteAlarms",
            format!(
                "Action=DeleteAlarms&Version=2010-08-01&AlarmNames.member.1={}",
                enc(name)
            ),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::{
        handler::NativeHandler,
        registry::{AwsProtocol, ServiceMetadata},
    };
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Monitoring {
        calls: Mutex<Vec<String>>,
        fail: Mutex<bool>,
    }
    #[async_trait::async_trait]
    impl NativeHandler for Monitoring {
        async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
            assert_eq!(request.account_id, "123456789012");
            assert_eq!(request.region, "us-west-2");
            assert_eq!(
                request.headers[http::header::CONTENT_TYPE],
                "application/x-www-form-urlencoded"
            );
            let form = String::from_utf8(request.body.to_vec()).unwrap();
            self.calls.lock().unwrap().push(form.clone());
            let body = if form.contains("Action=DescribeAlarms") {
                "<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms/></DescribeAlarmsResult></DescribeAlarmsResponse>"
            } else {
                "<Response/>"
            };
            http::Response::builder()
                .status(if *self.fail.lock().unwrap() { 500 } else { 200 })
                .body(axum::body::Body::from(body))
                .unwrap()
        }
    }
    #[tokio::test]
    async fn basic_alarm_lifecycle_uses_scoped_query_and_rejects_unsupported_fields() {
        let registry = ServiceRegistry::with_known_services();
        let monitoring = Arc::new(Monitoring::default());
        registry.register_native(
            ServiceName::new("monitoring"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            monitoring.clone(),
        );
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-west-2".into(),
            "123456789012".into(),
        );
        let mut props = json!({"AlarmName":"ledger backlog", "Namespace":"AWS/SQS", "MetricName":"ApproximateAgeOfOldestMessage",
            "Dimensions":[{"Name":"QueueName","Value":"ledger & retry"}],"Statistic":"Maximum", "Period":60,"EvaluationPeriods":2,
            "DatapointsToAlarm":1,"Threshold":20,"ComparisonOperator":"GreaterThanThreshold","TreatMissingData":"notBreaching",
            "ActionsEnabled":true,"AlarmActions":["arn:aws:sns:us-west-2:123456789012:alerts"]});
        let resource = provisioner
            .provision("Backlog", "ledger", "AWS::CloudWatch::Alarm", &props)
            .await
            .unwrap();
        assert_eq!(resource.ref_value, "ledger backlog");
        assert_eq!(
            resource.attributes["Arn"],
            "arn:aws:cloudwatch:us-west-2:123456789012:alarm:ledger backlog"
        );
        let calls = monitoring.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        assert!(calls[0].contains("AlarmNames.member.1=ledger%20backlog"));
        assert!(calls[1].contains("Dimensions.member.1.Value=ledger%20%26%20retry"));
        assert!(calls[1].contains("AlarmActions.member.1=arn%3Aaws%3Asns"));
        let previous = props.clone();
        props["Threshold"] = json!(50);
        props["AlarmActions"] = json!([]);
        provisioner
            .update(
                "Backlog",
                "AWS::CloudWatch::Alarm",
                &resource,
                &previous,
                &props,
                Replacement::Update(ResourcePolicy::Delete),
            )
            .await
            .unwrap();
        let updated = monitoring.calls.lock().unwrap().last().unwrap().clone();
        assert!(updated.contains("Threshold=50"));
        assert!(!updated.contains("AlarmActions.member"));
        for key in [
            "Metrics",
            "ExtendedStatistic",
            "EvaluateLowSampleCountPercentile",
            "Tags",
        ] {
            let mut unsupported = props.clone();
            unsupported[key] = json!([]);
            let before = monitoring.calls.lock().unwrap().len();
            assert!(provisioner
                .provision("Bad", "ledger", "AWS::CloudWatch::Alarm", &unsupported)
                .await
                .is_err());
            assert_eq!(monitoring.calls.lock().unwrap().len(), before);
        }
        let mut renamed = props.clone();
        renamed["AlarmName"] = json!("replacement");
        let before = monitoring.calls.lock().unwrap().len();
        assert!(provisioner
            .update(
                "Backlog",
                "AWS::CloudWatch::Alarm",
                &resource,
                &props,
                &renamed,
                Replacement::Update(ResourcePolicy::Delete)
            )
            .await
            .is_err());
        assert_eq!(monitoring.calls.lock().unwrap().len(), before);
        provisioner
            .deprovision("AWS::CloudWatch::Alarm", &resource.ref_value, &props)
            .await
            .unwrap();
        assert!(monitoring
            .calls
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("Action=DeleteAlarms"));
        *monitoring.fail.lock().unwrap() = true;
        assert!(provisioner
            .deprovision("AWS::CloudWatch::Alarm", &resource.ref_value, &props)
            .await
            .is_err());
    }
}
