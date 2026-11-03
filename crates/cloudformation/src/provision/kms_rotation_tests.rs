use super::*;
use locallycloud_core::handler::NativeHandler;
use std::sync::{Arc, Mutex};
#[derive(Default)]
struct State {
    enabled: bool,
    period: u64,
    tags: Vec<Value>,
    scheduled: bool,
    calls: Vec<String>,
    fail: Vec<String>,
}
struct Fixture(Mutex<State>);
#[async_trait::async_trait]
impl NativeHandler for Fixture {
    async fn handle(&self, request: ServiceRequest) -> axum::response::Response {
        let operation = request.headers["x-amz-target"].to_str().unwrap().to_owned();
        let input: Value = serde_json::from_slice(&request.body).unwrap();
        let mut state = self.0.lock().unwrap();
        state.calls.push(operation.clone());
        if state
            .fail
            .first()
            .is_some_and(|name| operation.ends_with(name))
        {
            state.fail.remove(0);
            return http::Response::builder()
                .status(400)
                .body(axum::body::Body::from("injected failure"))
                .unwrap();
        }
        let output = match operation.as_str() {
            "TrentService.CreateKey" => {
                state.tags = input["Tags"].as_array().cloned().unwrap_or_default();
                json!({"KeyMetadata":{"KeyId":"key","Arn":"arn:aws:kms:us-east-1:111111111111:key/key"}})
            }
            "TrentService.EnableKeyRotation" => {
                state.enabled = true;
                state.period = input["RotationPeriodInDays"].as_u64().unwrap();
                Value::Null
            }
            "TrentService.DisableKeyRotation" => {
                state.enabled = false;
                Value::Null
            }
            "TrentService.GetKeyRotationStatus" => {
                json!({"KeyRotationEnabled":state.enabled,"RotationPeriodInDays":state.period})
            }
            "TrentService.ListResourceTags" => json!({"Tags":state.tags}),
            "TrentService.TagResource" => {
                for new in input["Tags"].as_array().unwrap() {
                    state.tags.retain(|old| old["TagKey"] != new["TagKey"]);
                    state.tags.push(new.clone());
                }
                Value::Null
            }
            "TrentService.UntagResource" => {
                state.tags.retain(|old| {
                    !input["TagKeys"]
                        .as_array()
                        .unwrap()
                        .contains(&old["TagKey"])
                });
                Value::Null
            }
            "TrentService.ScheduleKeyDeletion" => {
                state.scheduled = true;
                json!({})
            }
            _ => panic!("unexpected {operation}"),
        };
        http::Response::builder()
            .status(200)
            .body(if output.is_null() {
                axum::body::Body::empty()
            } else {
                axum::body::Body::from(output.to_string())
            })
            .unwrap()
    }
}
#[tokio::test]
async fn rotation_create_update_and_tag_failure_compensation_use_native_calls() {
    let registry = Arc::new(ServiceRegistry::with_known_services());
    let fixture = Arc::new(Fixture(Mutex::new(State::default())));
    registry.register_native(
        ServiceName::new("kms"),
        locallycloud_core::registry::ServiceMetadata::new(
            locallycloud_core::registry::AwsProtocol::Json11,
            None,
        ),
        fixture.clone(),
    );
    let p = Provisioner::new(
        Arc::downgrade(&registry),
        "us-east-1".into(),
        "111111111111".into(),
    );
    let old = json!({"EnableKeyRotation":true,"RotationPeriodInDays":90,"Tags":[{"Key":"owner","Value":"old"}]});
    let current = p.kms_key("Key", &old).await.unwrap();
    {
        let state = fixture.0.lock().unwrap();
        assert!(state.enabled);
        assert_eq!(state.period, 90);
    }
    let next = json!({"EnableKeyRotation":false,"Tags":[{"Key":"review","Value":"new"}]});
    fixture.0.lock().unwrap().fail = vec!["TagResource".into()];
    assert!(p
        .update_kms_key("Key", &current, &old, &next)
        .await
        .is_err());
    {
        let state = fixture.0.lock().unwrap();
        assert!(state.enabled);
        assert_eq!(state.period, 90);
        assert_eq!(
            state.tags,
            json!([{"TagKey":"owner","TagValue":"old"}])
                .as_array()
                .unwrap()
                .clone()
        );
    }
    fixture.0.lock().unwrap().fail = vec!["DisableKeyRotation".into()];
    assert!(p
        .update_kms_key("Key", &current, &old, &next)
        .await
        .is_err());
    assert!(fixture.0.lock().unwrap().enabled);
    fixture.0.lock().unwrap().fail = vec!["TagResource".into(), "EnableKeyRotation".into()];
    let failure = p
        .update_kms_key("Key", &current, &old, &next)
        .await
        .unwrap_err();
    assert!(failure
        .to_string()
        .contains("cleanup after provisioning failure also failed"));
    p.update_kms_key("Key", &current, &old, &next)
        .await
        .unwrap();
    {
        let state = fixture.0.lock().unwrap();
        assert!(!state.enabled);
        assert_eq!(
            state.tags,
            json!([{"TagKey":"review","TagValue":"new"}])
                .as_array()
                .unwrap()
                .clone()
        );
    }
    let before = fixture.0.lock().unwrap().calls.len();
    for invalid in [
        json!({"EnableKeyRotation":"true"}),
        json!({"EnableKeyRotation":true,"RotationPeriodInDays":89}),
        json!({"RotationPeriodInDays":90}),
    ] {
        assert!(p.kms_key("Invalid", &invalid).await.is_err());
    }
    assert_eq!(fixture.0.lock().unwrap().calls.len(), before);
    fixture.0.lock().unwrap().fail = vec!["EnableKeyRotation".into()];
    assert!(p.kms_key("Cleanup", &old).await.is_err());
    assert!(fixture.0.lock().unwrap().scheduled);
}
