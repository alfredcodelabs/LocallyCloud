//! End-to-end IAM/STS tests driving the real registered handlers through the Core registry
//! (no mocks): user/role lifecycle, AssumeRole→GetCallerIdentity linkage, SimulateCustomPolicy,
//! and concurrent same-name creates yielding exactly one resource. Strict-mode enforcement is
//! covered by `enforcement.rs` unit tests and a live `awslocal` check.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method};

use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{ServiceName, ServiceRegistry};

fn registry() -> Arc<ServiceRegistry> {
    let reg = ServiceRegistry::with_known_services();
    localcloud_iam_sts::register(&reg);
    reg
}

fn handler(reg: &Arc<ServiceRegistry>, service: &str) -> Arc<dyn NativeHandler> {
    reg.native_handler(&ServiceName::new(service)).unwrap()
}

fn query_req(service: &str, body: &str) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("AWS4-HMAC-SHA256 Credential=test/20260101/us-east-1/{service}/aws4_request")
            .parse()
            .unwrap(),
    );
    ServiceRequest {
        method: Method::POST,
        uri: "/".parse().unwrap(),
        headers,
        body: Bytes::from(body.to_string()),
        region: "us-east-1".into(),
        account_id: "000000000000".into(),
        request_id: "rid".into(),
    }
}

async fn status_body(resp: axum::response::Response) -> (u16, String) {
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn between<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(&xml[start..end])
}

#[tokio::test]
async fn iam_create_and_get_user() {
    let reg = registry();
    let iam = handler(&reg, "iam");

    let (s, body) = status_body(
        iam.handle(query_req("iam", "Action=CreateUser&UserName=alice"))
            .await,
    )
    .await;
    assert_eq!(s, 200, "{body}");
    assert!(body.contains("<UserName>alice</UserName>"));

    let (s, body) = status_body(
        iam.handle(query_req("iam", "Action=GetUser&UserName=alice"))
            .await,
    )
    .await;
    assert_eq!(s, 200);
    assert!(body.contains("<UserName>alice</UserName>"));

    // Missing user is a 404 NoSuchEntity (AWS-faithful).
    let (s, body) = status_body(
        iam.handle(query_req("iam", "Action=GetUser&UserName=ghost"))
            .await,
    )
    .await;
    assert_eq!(s, 404);
    assert!(body.contains("<Code>NoSuchEntity</Code>"));
}

#[tokio::test]
async fn assume_role_links_to_caller_identity() {
    let reg = registry();
    let iam = handler(&reg, "iam");
    let sts = handler(&reg, "sts");
    let trust = r#"{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#;
    let create_role = format!(
        "Action=CreateRole&RoleName=app&AssumeRolePolicyDocument={}",
        urlencode(trust)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_role)).await).await;
    assert_eq!(status, 200, "{xml}");

    let missing =
        "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/missing&RoleSessionName=sess1";
    let (status, xml) = status_body(sts.handle(query_req("sts", missing)).await).await;
    assert_eq!(status, 404, "{xml}");
    assert!(xml.contains("<Code>NoSuchEntity</Code>"));

    let body = "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/app&RoleSessionName=sess1";
    let (s, xml) = status_body(sts.handle(query_req("sts", body)).await).await;
    assert_eq!(s, 200, "{xml}");
    let access_key = between(&xml, "AccessKeyId").expect("AccessKeyId in AssumeRole response");
    assert!(
        access_key.starts_with("ASIA"),
        "temporary key uses ASIA prefix: {access_key}"
    );
    assert!(xml.contains("assumed-role/app/sess1"));

    // GetCallerIdentity signed with the session key resolves to the assumed-role ARN.
    let req = query_req("sts", "Action=GetCallerIdentity");
    let mut req = req;
    req.headers.insert(
        "authorization",
        format!("AWS4-HMAC-SHA256 Credential={access_key}/20260101/us-east-1/sts/aws4_request")
            .parse()
            .unwrap(),
    );
    let (s, xml) = status_body(sts.handle(req).await).await;
    assert_eq!(s, 200);
    assert!(
        xml.contains("assumed-role/app/sess1"),
        "caller identity reflects the session: {xml}"
    );
}

#[tokio::test]
async fn malformed_policies_are_rejected_before_state_changes() {
    let reg = registry();
    let iam = handler(&reg, "iam");
    let malformed = r#"{"Statement":{"Action":"s3:*","Resource":"*"}}"#;
    let valid = r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}"#;
    let trust = r#"{"Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#;

    let create_bad = format!(
        "Action=CreatePolicy&PolicyName=bad-policy&PolicyDocument={}",
        urlencode(malformed)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_bad)).await).await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>MalformedPolicyDocument</Code>"));
    let (status, _) = status_body(
        iam.handle(query_req(
            "iam",
            "Action=GetPolicy&PolicyArn=arn:aws:iam::000000000000:policy/bad-policy",
        ))
        .await,
    )
    .await;
    assert_eq!(status, 404);

    let invalid_trust = r#"{"Statement":{"Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}}"#;
    let create_bad_role = format!(
        "Action=CreateRole&RoleName=bad-role&AssumeRolePolicyDocument={}",
        urlencode(invalid_trust)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_bad_role)).await).await;
    assert_eq!(status, 400, "{xml}");
    let (status, _) = status_body(
        iam.handle(query_req("iam", "Action=GetRole&RoleName=bad-role"))
            .await,
    )
    .await;
    assert_eq!(status, 404);

    let create_role = format!(
        "Action=CreateRole&RoleName=policy-role&AssumeRolePolicyDocument={}",
        urlencode(trust)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_role)).await).await;
    assert_eq!(status, 200, "{xml}");
    let update_role = format!(
        "Action=UpdateAssumeRolePolicy&RoleName=policy-role&PolicyDocument={}",
        urlencode(invalid_trust)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &update_role)).await).await;
    assert_eq!(status, 400, "{xml}");
    let (status, xml) = status_body(
        iam.handle(query_req("iam", "Action=GetRole&RoleName=policy-role"))
            .await,
    )
    .await;
    assert_eq!(status, 200, "{xml}");
    assert!(xml.contains("Effect%22%3A%22Allow"), "{xml}");

    let create_policy = format!(
        "Action=CreatePolicy&PolicyName=versioned&PolicyDocument={}",
        urlencode(valid)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_policy)).await).await;
    assert_eq!(status, 200, "{xml}");
    let policy_arn = "arn:aws:iam::000000000000:policy/versioned";
    let create_version = format!(
        "Action=CreatePolicyVersion&PolicyArn={policy_arn}&SetAsDefault=true&PolicyDocument={}",
        urlencode(malformed)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &create_version)).await).await;
    assert_eq!(status, 400, "{xml}");
    let (status, xml) = status_body(
        iam.handle(query_req(
            "iam",
            &format!("Action=ListPolicyVersions&PolicyArn={policy_arn}"),
        ))
        .await,
    )
    .await;
    assert_eq!(status, 200, "{xml}");
    assert_eq!(xml.matches("<member>").count(), 1, "{xml}");
    assert!(xml.contains("<VersionId>v1</VersionId>"), "{xml}");

    let put_valid = format!(
        "Action=PutRolePolicy&RoleName=policy-role&PolicyName=inline&PolicyDocument={}",
        urlencode(valid)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &put_valid)).await).await;
    assert_eq!(status, 200, "{xml}");
    let put_invalid = format!(
        "Action=PutRolePolicy&RoleName=policy-role&PolicyName=inline&PolicyDocument={}",
        urlencode(malformed)
    );
    let (status, xml) = status_body(iam.handle(query_req("iam", &put_invalid)).await).await;
    assert_eq!(status, 400, "{xml}");
    let (status, xml) = status_body(
        iam.handle(query_req(
            "iam",
            "Action=GetRolePolicy&RoleName=policy-role&PolicyName=inline",
        ))
        .await,
    )
    .await;
    assert_eq!(status, 200, "{xml}");
    assert!(xml.contains("s3%3AGetObject"), "{xml}");
}

#[tokio::test]
async fn simulate_custom_policy_reports_decision() {
    let reg = registry();
    let iam = handler(&reg, "iam");
    let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
    let body = format!(
        "Action=SimulateCustomPolicy&ActionNames.member.1=s3:GetObject&ResourceArns.member.1=*&PolicyInputList.member.1={}",
        urlencode(policy)
    );
    let (s, xml) = status_body(iam.handle(query_req("iam", &body)).await).await;
    assert_eq!(s, 200, "{xml}");
    assert!(
        xml.contains("<EvalDecision>allowed</EvalDecision>"),
        "{xml}"
    );
}

#[tokio::test]
async fn concurrent_same_name_create_yields_one_user() {
    let reg = registry();
    let iam = handler(&reg, "iam");

    let mut handles = Vec::new();
    for _ in 0..40u32 {
        let h = iam.clone();
        handles.push(tokio::spawn(async move {
            let resp = h
                .handle(query_req("iam", "Action=CreateUser&UserName=racer"))
                .await;
            resp.status().as_u16()
        }));
    }
    let mut ok = 0;
    let mut conflict = 0;
    for h in handles {
        match h.await.unwrap() {
            200 => ok += 1,
            409 => conflict += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert_eq!(ok, 1, "exactly one create succeeds");
    assert_eq!(conflict, 39, "the rest are EntityAlreadyExists");
}

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
