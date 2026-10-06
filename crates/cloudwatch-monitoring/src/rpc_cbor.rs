//! Smithy RPC v2 CBOR transport over the existing scoped JSON domain.
use super::*;
use ciborium::Value as Cbor;

const PREFIX: &str = "/service/GraniteServiceVersion20100801/operation/";
const PROTOCOL: &str = "rpc-v2-cbor";

pub(super) fn is_request(request: &ServiceRequest) -> bool {
    request.uri.path().starts_with("/service/")
        || request.headers.contains_key("smithy-protocol")
        || request
            .headers
            .get(http::header::CONTENT_TYPE)
            .is_some_and(|value| value == "application/cbor")
}

fn invalid(message: &str) -> MonitoringError {
    MonitoringError::InvalidParameter(message.into())
}

pub(super) fn decode(request: &ServiceRequest) -> Result<(String, Value), MonitoringError> {
    let action = request
        .uri
        .path()
        .strip_prefix(PREFIX)
        .filter(|action| {
            !action.is_empty()
                && action.len() <= 80
                && action.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .ok_or_else(|| invalid("invalid CloudWatch RPC operation path"))?;
    if request.method != http::Method::POST
        || request.uri.query().is_some()
        || request
            .headers
            .get("smithy-protocol")
            .is_none_or(|value| value != PROTOCOL)
        || request
            .headers
            .get(http::header::CONTENT_TYPE)
            .is_none_or(|value| value != "application/cbor")
    {
        return Err(invalid("RPC v2 CBOR requires POST, Smithy-Protocol rpc-v2-cbor and Content-Type application/cbor"));
    }
    let mut input = request.body.as_ref();
    let value: Cbor = ciborium::de::from_reader(&mut input)
        .map_err(|_| invalid("request body must be valid CBOR"))?;
    if !input.is_empty() {
        return Err(invalid("trailing CBOR data"));
    }
    let body = to_json(value, 0)?;
    if !body.is_object() {
        return Err(invalid("request must be a CBOR structure"));
    }
    Ok((action.to_owned(), body))
}

pub(super) fn to_json(value: Cbor, depth: usize) -> Result<Value, MonitoringError> {
    if depth > 64 {
        return Err(invalid("CBOR nesting exceeds supported limit"));
    }
    Ok(match value {
        Cbor::Null => Value::Null,
        Cbor::Bool(value) => json!(value),
        Cbor::Text(value) => Value::String(value),
        Cbor::Integer(value) => {
            let number = i128::from(value);
            if let Ok(value) = i64::try_from(number) {
                json!(value)
            } else if let Ok(value) = u64::try_from(number) {
                json!(value)
            } else {
                return Err(invalid("CBOR integer is outside supported range"));
            }
        }
        Cbor::Float(value) => Value::Number(
            serde_json::Number::from_f64(value)
                .ok_or_else(|| invalid("CBOR number must be finite"))?,
        ),
        Cbor::Tag(1, value) if matches!(value.as_ref(), Cbor::Integer(_) | Cbor::Float(_)) => {
            to_json(*value, depth + 1)?
        }
        Cbor::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| to_json(value, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        Cbor::Map(values) => {
            let mut result = serde_json::Map::new();
            for (key, value) in values {
                let Cbor::Text(key) = key else {
                    return Err(invalid("CBOR structure keys must be text"));
                };
                if result.insert(key, to_json(value, depth + 1)?).is_some() {
                    return Err(invalid("duplicate CBOR structure member"));
                }
            }
            Value::Object(result)
        }
        _ => return Err(invalid("unsupported CBOR type or tag")),
    })
}

fn from_json(value: Value, key: &str) -> Cbor {
    let value = match value {
        Value::Null => Cbor::Null,
        Value::Bool(value) => Cbor::Bool(value),
        Value::String(value) => Cbor::Text(value),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Cbor::Integer(value.into())
            } else if let Some(value) = value.as_u64() {
                Cbor::Integer(value.into())
            } else {
                Cbor::Float(value.as_f64().expect("JSON number"))
            }
        }
        Value::Array(values) => Cbor::Array(
            values
                .into_iter()
                .map(|value| from_json(value, key))
                .collect(),
        ),
        Value::Object(values) => Cbor::Map(
            values
                .into_iter()
                .map(|(key, value)| {
                    let value = from_json(value, &key);
                    (Cbor::Text(key), value)
                })
                .collect(),
        ),
    };
    if matches!(
        key,
        "Timestamp"
            | "StateUpdatedTimestamp"
            | "StateTransitionedTimestamp"
            | "AlarmConfigurationUpdatedTimestamp"
    ) && matches!(value, Cbor::Integer(_) | Cbor::Float(_))
    {
        Cbor::Tag(1, Box::new(value))
    } else {
        value
    }
}

pub(super) fn response(result: Result<Value, MonitoringError>, request_id: &str) -> Response {
    let (status, value) = match result {
        Ok(body) => (200, body),
        Err(error) => {
            let (code, status) = match &error {
                MonitoringError::AccessDenied => ("AccessDenied", 403),
                MonitoringError::NotFound(_) => ("ResourceNotFound", 404),
                MonitoringError::ResourceNotFoundException(_) => ("ResourceNotFoundException", 404),
                MonitoringError::InvalidAction(_) => ("InvalidAction", 400),
                MonitoringError::InvalidParameter(_) => ("InvalidParameterValue", 400),
                MonitoringError::InvalidNextToken(_) => ("InvalidNextToken", 400),
                MonitoringError::Internal(_) => ("InternalServiceError", 500),
            };
            (status, json!({"__type":code,"message":error.to_string()}))
        }
    };
    let mut body = Vec::new();
    ciborium::ser::into_writer(&from_json(value, ""), &mut body).expect("CBOR to Vec cannot fail");
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/cbor")
        .header("smithy-protocol", PROTOCOL)
        .header("x-amzn-RequestId", request_id)
        .body(Body::from(body))
        .expect("Monitoring CBOR response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(action: &str, body: Cbor) -> ServiceRequest {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&body, &mut bytes).unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("smithy-protocol", PROTOCOL.parse().unwrap());
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/cbor".parse().unwrap(),
        );
        ServiceRequest {
            method: http::Method::POST,
            uri: format!("{PREFIX}{action}").parse().unwrap(),
            headers,
            body: bytes.into(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "cbor-native".into(),
        }
    }

    async fn decoded(response: Response) -> Cbor {
        assert_eq!(response.headers()["smithy-protocol"], PROTOCOL);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE],
            "application/cbor"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        ciborium::de::from_reader(bytes.as_ref()).unwrap()
    }

    #[tokio::test]
    async fn cbor_alarm_lifecycle_reuses_scoped_domain_and_preserves_query() {
        let registry = Arc::new(ServiceRegistry::new());
        register(&registry);
        let handler = registry
            .native_handler(&ServiceName::new("monitoring"))
            .unwrap();
        let config = json!({"AlarmName":"orders","Namespace":"Orders","MetricName":"Errors","Statistic":"Sum","Period":60,"EvaluationPeriods":1,"Threshold":2,"ComparisonOperator":"GreaterThanThreshold","Dimensions":[{"Name":"QueueName","Value":"orders"}],"AlarmActions":[]});
        let response = handler
            .handle(request("PutMetricAlarm", from_json(config.clone(), "")))
            .await;
        assert_eq!(response.status(), 200);
        assert_eq!(to_json(decoded(response).await, 0).unwrap(), json!({}));
        let response = handler
            .handle(request(
                "DescribeAlarms",
                from_json(json!({"AlarmNames":["orders"]}), ""),
            ))
            .await;
        assert_eq!(response.status(), 200);
        let wire = decoded(response).await;
        let Cbor::Map(entries) = &wire else {
            panic!("output structure");
        };
        let Cbor::Array(alarms) = &entries
            .iter()
            .find(|(key, _)| *key == Cbor::Text("MetricAlarms".into()))
            .unwrap()
            .1
        else {
            panic!("alarms array");
        };
        let Cbor::Map(alarm) = &alarms[0] else {
            panic!("alarm structure");
        };
        assert!(alarm.iter().any(|(key, value)| *key
            == Cbor::Text("StateUpdatedTimestamp".into())
            && matches!(value, Cbor::Tag(1, _))));
        let described = to_json(wire, 0).unwrap();
        assert_eq!(described["MetricAlarms"][0]["AlarmName"], "orders");
        assert_eq!(
            described["MetricAlarms"][0]["Threshold"].as_f64(),
            Some(2.0)
        );
        let mut query = request("DescribeAlarms", Cbor::Map(vec![]));
        query.uri = "/".parse().unwrap();
        query.headers.clear();
        query.headers.insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        query.body = b"Action=DescribeAlarms&Version=2010-08-01&AlarmNames.member.1=orders"
            .to_vec()
            .into();
        let response = handler.handle(query).await;
        assert_eq!(response.status(), 200);
        let xml = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&xml)
            .unwrap()
            .contains("<AlarmName>orders</AlarmName>"));
        let resource = "arn:aws:cloudwatch:us-east-1:000000000000:alarm:orders";
        let response = handler
            .handle(request(
                "TagResource",
                from_json(
                    json!({"ResourceARN":resource,"Tags":[{"Key":"team","Value":"ledger"}]}),
                    "",
                ),
            ))
            .await;
        assert_eq!(response.status(), 200);
        let response = handler
            .handle(request(
                "ListTagsForResource",
                from_json(json!({"ResourceARN":resource}), ""),
            ))
            .await;
        assert_eq!(
            to_json(decoded(response).await, 0).unwrap()["Tags"],
            json!([{"Key":"team","Value":"ledger"}])
        );
        let mut invalid_request = request("PutMetricAlarm", from_json(config, ""));
        invalid_request.body = [invalid_request.body.as_ref(), &[0xf6]].concat().into();
        let response = handler.handle(invalid_request).await;
        assert_eq!(response.status(), 400);
        assert_eq!(
            to_json(decoded(response).await, 0).unwrap()["__type"],
            "InvalidParameterValue"
        );
        let response = handler
            .handle(request(
                "DeleteAlarms",
                from_json(json!({"AlarmNames":["orders"]}), ""),
            ))
            .await;
        assert_eq!(response.status(), 200);
        let response = handler
            .handle(request("DescribeAlarms", from_json(json!({}), "")))
            .await;
        assert_eq!(
            to_json(decoded(response).await, 0).unwrap()["MetricAlarms"],
            json!([])
        );
    }

    #[test]
    fn cbor_timestamp_and_malformed_contracts() {
        let body = from_json(
            json!({"MetricData":[{"MetricName":"Requests","Timestamp":1234.125,"Value":3}]}),
            "",
        );
        let request = request("PutMetricData", body);
        let (action, decoded) = decode(&request).unwrap();
        assert_eq!(action, "PutMetricData");
        assert_eq!(decoded["MetricData"][0]["Timestamp"], 1234.125);
        let mut wrong_protocol = request.clone();
        wrong_protocol.headers.remove("smithy-protocol");
        assert!(decode(&wrong_protocol).is_err());
        assert!(to_json(Cbor::Tag(2, Box::new(Cbor::Integer(1.into()))), 0).is_err());
        assert!(to_json(Cbor::Map(vec![(Cbor::Integer(1.into()), Cbor::Null)]), 0).is_err());
        assert_eq!(
            to_json(Cbor::Array(vec![Cbor::Null]), 0).unwrap(),
            json!([null])
        );
        let mut truncated = request;
        truncated.body = vec![0xbf].into();
        assert!(decode(&truncated).is_err());
    }
}
