//! Native CloudWatch policy guard using Core's verified identity and IAM capability.
use super::*;
use locallycloud_core::integration::{authorization::AuthorizationRequest, RequestIdentity};

pub(super) fn check(
    registry: &std::sync::Weak<ServiceRegistry>,
    request: &ServiceRequest,
    action: &str,
    resource: &str,
    mut context: BTreeMap<String, Vec<String>>,
) -> Result<(), MonitoringError> {
    let Some(registry) = registry.upgrade() else {
        return Ok(());
    };
    let Some(evaluator) = registry.authorization_evaluator(&ServiceName::new("iam")) else {
        return Ok(());
    };
    if !evaluator.strict_sigv4_required()
        || request
            .headers
            .get("x-locallycloud-verified-internal-scope")
            .is_some_and(|value| value == "1")
    {
        return Ok(());
    }
    if request
        .headers
        .get("x-locallycloud-verified-external-sigv4")
        .is_none_or(|value| value != "1")
    {
        return Err(MonitoringError::AccessDenied);
    }
    let key = request
        .headers
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(RequestIdentity::access_key_from_authorization)
        .ok_or(MonitoringError::AccessDenied)?;
    context.insert("aws:requestedregion".into(), vec![request.region.clone()]);
    evaluator
        .authorize(AuthorizationRequest {
            request_identity: RequestIdentity {
                account_id: request.account_id.clone(),
                access_key_id: Some(key),
                arn: None,
            },
            delegated_identity: None,
            source_service: "monitoring".into(),
            action: format!("cloudwatch:{action}"),
            resource: resource.into(),
            context,
        })
        .map_err(|_| MonitoringError::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use locallycloud_core::integration::authorization::{
        AuthorizationError, AuthorizationEvaluator,
    };
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Policies {
        allowed: Mutex<BTreeSet<(String, String)>>,
        requests: Mutex<Vec<AuthorizationRequest>>,
    }
    impl AuthorizationEvaluator for Policies {
        fn strict_sigv4_required(&self) -> bool {
            true
        }
        fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
            let allowed = self
                .allowed
                .lock()
                .unwrap()
                .contains(&(request.action.clone(), request.resource.clone()));
            self.requests.lock().unwrap().push(request);
            if allowed {
                Ok(())
            } else {
                Err(AuthorizationError::Denied)
            }
        }
    }
    fn request(action: &str, body: Value) -> ServiceRequest {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        let mut headers = http::HeaderMap::new();
        for (key,value) in [("content-type","application/cbor"),("smithy-protocol","rpc-v2-cbor"),("x-locallycloud-verified-external-sigv4","1"),("authorization","AWS4-HMAC-SHA256 Credential=KEY/20261006/us-east-1/monitoring/aws4_request, SignedHeaders=host, Signature=invalid-in-direct-test")] { headers.insert(key,value.parse().unwrap()); }
        ServiceRequest {
            method: http::Method::POST,
            uri: format!("/service/GraniteServiceVersion20100801/operation/{action}")
                .parse()
                .unwrap(),
            headers,
            body: bytes.into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "iam-monitoring".into(),
        }
    }

    #[tokio::test]
    async fn strict_monitoring_guard_rechecks_policy_before_effects_across_protocols() {
        let registry = Arc::new(ServiceRegistry::new());
        register(&registry);
        let handler = registry
            .native_handler(&ServiceName::new("monitoring"))
            .unwrap();
        let policies = Arc::new(Policies::default());
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            handler.clone(),
            policies.clone(),
        );
        let resource = "arn:aws:cloudwatch:us-east-1:000000000000:alarm:orders";
        let config = json!({"AlarmName":"orders","Namespace":"Orders","MetricName":"Errors","Statistic":"Sum","Period":60,"EvaluationPeriods":1,"Threshold":2,"ComparisonOperator":"GreaterThanThreshold","Tags":[{"Key":"team","Value":"orders"}]});
        let response = handler
            .handle(request("PutMetricAlarm", config.clone()))
            .await;
        assert_eq!(response.status(), 403);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        assert_eq!(body["__type"], "AccessDenied");
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:PutMetricAlarm".into(), resource.into()));
        assert_eq!(
            handler
                .handle(request("PutMetricAlarm", config.clone()))
                .await
                .status(),
            403
        ); // Dependent tagging permission is required.
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:DescribeAlarms".into(), resource.into()));
        let response = handler
            .handle(request("DescribeAlarms", json!({"AlarmNames":["orders"]})))
            .await;
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        assert_eq!(body["MetricAlarms"], json!([]));
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:TagResource".into(), resource.into()));
        assert_eq!(
            handler
                .handle(request("PutMetricAlarm", config.clone()))
                .await
                .status(),
            200
        );
        let seen = policies.requests.lock().unwrap().last().unwrap().clone();
        assert_eq!(seen.action, "cloudwatch:TagResource");
        assert_eq!(seen.context["aws:requesttag/team"], vec!["orders"]);
        assert_eq!(seen.context["aws:tagkeys"], vec!["team"]);
        assert_eq!(seen.context["aws:requestedregion"], vec!["us-east-1"]);
        policies
            .allowed
            .lock()
            .unwrap()
            .remove(&("cloudwatch:TagResource".into(), resource.into()));
        assert_eq!(
            handler
                .handle(request("PutMetricAlarm", config))
                .await
                .status(),
            200
        ); // Existing-alarm Tags ignored, no dependent tag permission.
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:ListTagsForResource".into(), resource.into()));
        let mut query = request("TagResource", json!({}));
        query.uri = "/".parse().unwrap();
        query.headers.remove("smithy-protocol");
        query.headers.insert(
            "content-type",
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        query.body=format!("Action=TagResource&ResourceARN={resource}&Tags.member.1.Key=team&Tags.member.1.Value=denied").into_bytes().into();
        let response = handler.handle(query).await;
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["content-type"], "application/xml");
        let response = handler
            .handle(request(
                "ListTagsForResource",
                json!({"ResourceARN":resource}),
            ))
            .await;
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: Value = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        assert_eq!(body["Tags"], json!([{"Key":"team","Value":"orders"}]));
        let seen = policies.requests.lock().unwrap().last().unwrap().clone();
        assert_eq!(seen.context["aws:resourcetag/team"], vec!["orders"]);
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:DeleteAlarms".into(), resource.into()));
        assert_eq!(
            handler
                .handle(request(
                    "DeleteAlarms",
                    json!({"AlarmNames":["orders","denied"]})
                ))
                .await
                .status(),
            403
        );
        let response = handler
            .handle(request("DescribeAlarms", json!({"AlarmNames":["orders"]})))
            .await;
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let body: ciborium::Value = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        let body = crate::rpc_cbor::to_json(body, 0).unwrap();
        assert_eq!(body["MetricAlarms"].as_array().unwrap().len(), 1);
        let mut trusted = request("DeleteAlarms", json!({"AlarmNames":["orders"]}));
        trusted.headers.remove("authorization");
        trusted.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert_eq!(handler.handle(trusted).await.status(), 200);
        let mut forged = request("ListMetrics", json!({}));
        forged
            .headers
            .remove("x-locallycloud-verified-external-sigv4");
        assert_eq!(handler.handle(forged).await.status(), 403);
        policies
            .allowed
            .lock()
            .unwrap()
            .insert(("cloudwatch:ListMetrics".into(), "*".into()));
        assert_eq!(
            handler
                .handle(request("ListMetrics", json!({})))
                .await
                .status(),
            200
        );
    }
}
