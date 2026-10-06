//! Service-boundary checks use real IAM records and policy evaluation. Core's signed
//! ingress/transport gates are separate: attestation headers here are trusted fixture inputs.
use axum::{body::to_bytes, response::Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::{
    handler::{NativeHandler, ServiceRequest},
    integration::{
        authorization::{
            AuthorizationError, AuthorizationEvaluator, AuthorizationRequest, ResourcePolicyError,
        },
        RequestIdentity,
    },
    registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry},
};
use std::{collections::BTreeMap, sync::Arc};

const OWNER: &str = "000000000000";
const OTHER: &str = "111111111111";

struct StrictEvaluator(Arc<dyn AuthorizationEvaluator>);
impl AuthorizationEvaluator for StrictEvaluator {
    fn strict_sigv4_required(&self) -> bool {
        true
    }
    fn authorize(&self, request: AuthorizationRequest) -> Result<(), AuthorizationError> {
        self.0.authorize(request)
    }
    fn resolve_caller_arn(
        &self,
        request: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        self.0.resolve_caller_arn(request)
    }
    fn validate_resource_policy(&self, document: &str) -> Result<(), ResourcePolicyError> {
        self.0.validate_resource_policy(document)
    }
    fn authorize_resource_policy(
        &self,
        request: AuthorizationRequest,
        document: Option<&str>,
        owner: &str,
    ) -> Result<(), AuthorizationError> {
        self.0.authorize_resource_policy(request, document, owner)
    }
}

/// A root-looking ARN is deliberately unrelated to authenticated root provenance.
struct ForgedRootArnEvaluator(Arc<dyn AuthorizationEvaluator>);
impl AuthorizationEvaluator for ForgedRootArnEvaluator {
    fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }
    fn strict_sigv4_required(&self) -> bool {
        true
    }
    fn resolve_caller_arn(
        &self,
        _request: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        Ok(Some(format!("arn:aws:iam::{OWNER}:root")))
    }
    fn validate_resource_policy(&self, document: &str) -> Result<(), ResourcePolicyError> {
        self.0.validate_resource_policy(document)
    }
    fn authorize_resource_policy(
        &self,
        _request: AuthorizationRequest,
        _document: Option<&str>,
        _owner: &str,
    ) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }
    // Use the trait's fail-closed default for is_account_root.
}

struct ForeignRootEvaluator(ForgedRootArnEvaluator);
impl AuthorizationEvaluator for ForeignRootEvaluator {
    fn authorize(&self, _: AuthorizationRequest) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::Denied)
    }
    fn strict_sigv4_required(&self) -> bool {
        true
    }
    fn is_account_root(&self, identity: &RequestIdentity) -> Result<bool, AuthorizationError> {
        Ok(identity.account_id == OTHER)
    }
    fn resolve_caller_arn(
        &self,
        _request: &RequestIdentity,
    ) -> Result<Option<String>, AuthorizationError> {
        Ok(Some(format!("arn:aws:iam::{OTHER}:root")))
    }
    fn validate_resource_policy(&self, document: &str) -> Result<(), ResourcePolicyError> {
        self.0.validate_resource_policy(document)
    }
    fn authorize_resource_policy(
        &self,
        request: AuthorizationRequest,
        document: Option<&str>,
        owner: &str,
    ) -> Result<(), AuthorizationError> {
        self.0.authorize_resource_policy(request, document, owner)
    }
}
fn request(
    method: Method,
    path: &str,
    body: &str,
    account: &str,
    key: Option<&str>,
) -> ServiceRequest {
    let mut headers = HeaderMap::new();
    if let Some(key) = key {
        headers.insert(
            "x-locallycloud-verified-external-sigv4",
            HeaderValue::from_static("1"),
        );
        headers.insert(
            "x-locallycloud-verified-secure-transport",
            HeaderValue::from_static("false"),
        );
        headers.insert("authorization", HeaderValue::from_str(&format!("AWS4-HMAC-SHA256 Credential={key}/20261006/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=fixture")).unwrap());
    }
    ServiceRequest {
        method,
        uri: path.parse().unwrap(),
        headers,
        body: Bytes::copy_from_slice(body.as_bytes()),
        region: "us-east-1".into(),
        account_id: account.into(),
        request_id: "policy-fixture".into(),
    }
}
async fn body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
fn xml(body: &str, tag: &str) -> String {
    body.split(&format!("<{tag}>"))
        .nth(1)
        .unwrap()
        .split(&format!("</{tag}>"))
        .next()
        .unwrap()
        .into()
}
fn encode(value: &str) -> String {
    value.bytes().map(|b| format!("%{b:02X}")).collect()
}
async fn iam(
    registry: &ServiceRegistry,
    account: &str,
    action: &str,
    fields: &[(&str, &str)],
) -> String {
    let mut value = format!("Action={action}&Version=2010-05-08");
    for (key, field) in fields {
        value.push_str(&format!("&{key}={}", encode(field)));
    }
    let handler = registry.native_handler(&ServiceName::new("iam")).unwrap();
    let response = handler
        .handle(request(Method::POST, "/", &value, account, None))
        .await;
    let status = response.status();
    let response = body(response).await;
    assert!(status.is_success(), "{response}");
    response
}
struct Fixture {
    registry: Arc<ServiceRegistry>,
    s3: Arc<dyn NativeHandler>,
    admin: String,
    reader: String,
    outsider: String,
}
impl Fixture {
    async fn new() -> Self {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_iam_sts::register(&registry);
        let mut keys = BTreeMap::new();
        for (account, user) in [(OWNER, "admin"), (OWNER, "reader"), (OTHER, "outsider")] {
            iam(&registry, account, "CreateUser", &[("UserName", user)]).await;
            let key = iam(&registry, account, "CreateAccessKey", &[("UserName", user)]).await;
            keys.insert(user, xml(&key, "AccessKeyId"));
        }
        iam(
            &registry,
            OWNER,
            "PutUserPolicy",
            &[
                ("UserName", "admin"),
                ("PolicyName", "admin"),
                (
                    "PolicyDocument",
                    r#"{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#,
                ),
            ],
        )
        .await;
        iam(
            &registry,
            OTHER,
            "PutUserPolicy",
            &[
                ("UserName", "outsider"),
                ("PolicyName", "read"),
                (
                    "PolicyDocument",
                    r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#,
                ),
            ],
        )
        .await;
        locallycloud_s3::register(&registry);
        let s3 = registry.native_handler(&ServiceName::new("s3")).unwrap();
        for bucket in ["policy-source", "policy-dest"] {
            assert_eq!(
                s3.handle(request(Method::PUT, &format!("/{bucket}"), "", OWNER, None))
                    .await
                    .status(),
                200
            );
            assert_eq!(
                s3.handle(request(
                    Method::PUT,
                    &format!("/{bucket}/key"),
                    "original",
                    OWNER,
                    None
                ))
                .await
                .status(),
                200
            );
        }
        let evaluator = registry
            .authorization_evaluator(&ServiceName::new("iam"))
            .unwrap();
        let handler = registry.native_handler(&ServiceName::new("iam")).unwrap();
        registry.register_native_with_authorization_evaluator(
            ServiceName::new("iam"),
            ServiceMetadata::new(AwsProtocol::Query, None),
            handler,
            Arc::new(StrictEvaluator(evaluator)),
        );
        Self {
            registry,
            s3,
            admin: keys.remove("admin").unwrap(),
            reader: keys.remove("reader").unwrap(),
            outsider: keys.remove("outsider").unwrap(),
        }
    }
    async fn policy(&self, bucket: &str, policy: &str) -> Response {
        self.s3
            .handle(request(
                Method::PUT,
                &format!("/{bucket}?policy"),
                policy,
                OWNER,
                Some(&self.admin),
            ))
            .await
    }
}

#[tokio::test]
async fn root_looking_arn_without_provenance_cannot_recover_bucket_policy() {
    let f = Fixture::new().await;
    assert_policy_recovery_denied(&f, OWNER, false).await;
}

#[tokio::test]
async fn foreign_root_provenance_cannot_recover_owner_bucket_policy() {
    let f = Fixture::new().await;
    assert_policy_recovery_denied(&f, OTHER, true).await;
}

async fn assert_policy_recovery_denied(f: &Fixture, caller: &str, foreign_root: bool) {
    let policy = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::policy-source","arn:aws:s3:::policy-source/*"]}}"#;
    assert_eq!(f.policy("policy-source", policy).await.status(), 204);
    let evaluator = f
        .registry
        .authorization_evaluator(&ServiceName::new("iam"))
        .unwrap();
    let fake = ForgedRootArnEvaluator(evaluator);
    let evaluator: Arc<dyn AuthorizationEvaluator> = if foreign_root {
        Arc::new(ForeignRootEvaluator(fake))
    } else {
        Arc::new(fake)
    };
    let handler = f.registry.native_handler(&ServiceName::new("iam")).unwrap();
    f.registry.register_native_with_authorization_evaluator(
        ServiceName::new("iam"),
        ServiceMetadata::new(AwsProtocol::Query, None),
        handler,
        evaluator,
    );
    let key = if foreign_root { &f.outsider } else { &f.admin };
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let response =
            f.s3.handle(request(
                method.clone(),
                "/policy-source?policy",
                policy,
                caller,
                Some(key),
            ))
            .await;
        assert_eq!(response.status(), 403, "{method}");
        assert!(body(response).await.contains("<Code>AccessDenied</Code>"));
    }
}

#[tokio::test]
async fn validation_does_not_replace_the_last_valid_policy() {
    let f = Fixture::new().await;
    let valid = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", valid).await.status(), 204);
    for policy in [
        "not JSON",
        "{}",
        r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::another-bucket/*"}}"#,
    ] {
        let response = f.policy("policy-source", policy).await;
        assert_eq!(response.status(), 400);
        assert!(body(response)
            .await
            .contains("<Code>MalformedPolicy</Code>"));
    }
    let oversized = format!("{valid}{}", " ".repeat(20 * 1024));
    let response = f.policy("policy-source", &oversized).await;
    assert_eq!(response.status(), 400);
    assert!(body(response)
        .await
        .contains("<Code>MalformedPolicy</Code>"));
    let unsupported = r#"{"Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*","Condition":{"StringEquals":{"s3:unknown-condition":"x"}}}}"#;
    let response = f.policy("policy-source", unsupported).await;
    assert_eq!(response.status(), 501);
    assert!(body(response).await.contains("<Code>NotImplemented</Code>"));
    let response =
        f.s3.handle(request(
            Method::GET,
            "/policy-source?policy",
            "",
            OWNER,
            Some(&f.admin),
        ))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await, valid);
}

#[tokio::test]
async fn resource_allow_explicit_denies_transport_and_revoked_identity() {
    let f = Fixture::new().await;
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OWNER,
            Some(&f.reader)
        ))
        .await
        .status(),
        403
    );
    let allow = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", allow).await.status(), 204);
    let response =
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OWNER,
            Some(&f.reader),
        ))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await, "original");
    let deny_http = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::policy-source","arn:aws:s3:::policy-source/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}}"#;
    assert_eq!(f.policy("policy-source", deny_http).await.status(), 204);
    let mut read = request(Method::GET, "/policy-source/key", "", OWNER, Some(&f.admin));
    read.headers
        .insert("x-forwarded-proto", HeaderValue::from_static("https"));
    assert_eq!(f.s3.handle(read).await.status(), 403);
    let mut recovery = request(
        Method::DELETE,
        "/policy-source?policy",
        "",
        OWNER,
        Some(&f.admin),
    );
    recovery.headers.insert(
        "x-locallycloud-verified-secure-transport",
        HeaderValue::from_static("true"),
    );
    assert_eq!(f.s3.handle(recovery).await.status(), 204);
    assert_eq!(f.policy("policy-source", allow).await.status(), 204);
    iam(
        &f.registry,
        OWNER,
        "UpdateAccessKey",
        &[
            ("UserName", "reader"),
            ("AccessKeyId", &f.reader),
            ("Status", "Inactive"),
        ],
    )
    .await;
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OWNER,
            Some(&f.reader)
        ))
        .await
        .status(),
        403
    );
}

#[tokio::test]
async fn denied_source_copy_and_multipart_do_not_mutate_objects() {
    let f = Fixture::new().await;
    let deny_read = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", deny_read).await.status(), 204);
    let mut copy = request(Method::PUT, "/policy-dest/key", "", OWNER, Some(&f.admin));
    copy.headers.insert(
        "x-amz-copy-source",
        HeaderValue::from_static("/policy-source/key"),
    );
    assert_eq!(f.s3.handle(copy).await.status(), 403);
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-dest/key",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "original"
    );
    let deny_write = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::policy-dest/*"}}"#;
    assert_eq!(f.policy("policy-dest", deny_write).await.status(), 204);
    assert_eq!(
        f.s3.handle(request(
            Method::POST,
            "/policy-dest/key?uploads",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        403
    );
    let response =
        f.s3.handle(request(
            Method::GET,
            "/policy-dest?uploads",
            "",
            OWNER,
            Some(&f.admin),
        ))
        .await;
    assert_eq!(response.status(), 200);
    assert!(!body(response).await.contains("<Upload>"));
}

#[tokio::test]
async fn cross_account_reads_use_owner_storage_and_revoke_immediately() {
    let f = Fixture::new().await;
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        403
    );
    let allow = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/outsider"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", allow).await.status(), 204);
    let response =
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OTHER,
            Some(&f.outsider),
        ))
        .await;
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await, "original");
    assert_eq!(f.policy("policy-source", r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#).await.status(), 204);
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        403
    );
    assert_eq!(
        f.s3.handle(request(
            Method::DELETE,
            "/policy-source?policy",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        204
    );
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/key",
            "",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        403
    );
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-source/key",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "original"
    );
}

#[tokio::test]
async fn delegated_roles_and_service_principals_do_not_bypass_policy() {
    let f = Fixture::new().await;
    iam(&f.registry, OWNER, "CreateRole", &[("RoleName", "worker"), ("AssumeRolePolicyDocument", r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"sts:AssumeRole"}}"#)]).await;
    iam(&f.registry, OWNER, "PutRolePolicy", &[("RoleName", "worker"), ("PolicyName", "read"), ("PolicyDocument", r#"{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#)]).await;
    let mut delegated = request(Method::GET, "/policy-source/key", "", OWNER, None);
    delegated.headers.insert(
        "x-locallycloud-verified-internal-scope",
        HeaderValue::from_static("1"),
    );
    delegated.headers.insert(
        "x-locallycloud-caller-principal",
        HeaderValue::from_static("arn:aws:iam::000000000000:role/worker/execution"),
    );
    assert_eq!(f.s3.handle(delegated.clone()).await.status(), 200);
    let deny = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", deny).await.status(), 204);
    assert_eq!(f.s3.handle(delegated.clone()).await.status(), 403);
    assert_eq!(
        f.s3.handle(request(
            Method::DELETE,
            "/policy-source?policy",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        204
    );
    // Internal role transport is absent after Core redaction; it is not invented as HTTP.
    let deny_http = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}}"#;
    assert_eq!(f.policy("policy-source", deny_http).await.status(), 204);
    assert_eq!(f.s3.handle(delegated.clone()).await.status(), 200);
    // Role-based calls cannot supply AWS direct-service SourceArn/SourceAccount context.
    delegated.headers.insert(
        "x-locallycloud-source-arn",
        HeaderValue::from_static("arn:aws:states:us-east-1:000000000000:stateMachine:fixture"),
    );
    delegated.headers.insert(
        "x-locallycloud-source-account",
        HeaderValue::from_static(OWNER),
    );
    let deny_source = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*","Condition":{"Null":{"aws:SourceArn":"false","aws:SourceAccount":"false"}}}}"#;
    assert_eq!(f.policy("policy-source", deny_source).await.status(), 204);
    assert_eq!(f.s3.handle(delegated.clone()).await.status(), 200);
    let mut service = delegated.clone();
    service.headers.insert(
        "x-locallycloud-caller-principal",
        HeaderValue::from_static("states.amazonaws.com"),
    );
    // Without Source context this explicit Allow would pass; the matching Deny proves retention.
    let source_service_policy = r#"{"Statement":[{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*"},{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*","Condition":{"Null":{"aws:SourceArn":"false","aws:SourceAccount":"false"}}}]}"#;
    assert_eq!(
        f.policy("policy-source", source_service_policy)
            .await
            .status(),
        204
    );
    assert_eq!(f.s3.handle(service).await.status(), 403);
    delegated.headers.insert(
        "x-locallycloud-caller-principal",
        HeaderValue::from_static("states.amazonaws.com"),
    );
    assert_eq!(f.s3.handle(delegated.clone()).await.status(), 403);
    let service_allow = r#"{"Statement":{"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::policy-source/*","Condition":{"Bool":{"aws:PrincipalIsAWSService":"true"}}}}"#;
    assert_eq!(f.policy("policy-source", service_allow).await.status(), 204);
    assert_eq!(f.s3.handle(delegated).await.status(), 200);
}

#[tokio::test]
async fn list_conditions_use_decoded_prefix_and_actual_listing_parameters() {
    let f = Fixture::new().await;
    // IfExists must not turn a missing implementation context into unconditional Allow.
    let allow = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},"Action":["s3:ListBucket","s3:ListBucketVersions"],"Resource":"arn:aws:s3:::policy-source","Condition":{"StringLikeIfExists":{"s3:prefix":"allowed/*"},"StringEquals":{"s3:delimiter":"/"},"NumericLessThanEquals":{"s3:max-keys":"5"}}}}"#;
    assert_eq!(f.policy("policy-source", allow).await.status(), 204);
    for path in [
        "/policy-source?list-type=2&prefix=allowed%2F&delimiter=%2F&max-keys=5",
        "/policy-source?versions&prefix=allowed%2F&delimiter=%2F&max-keys=1",
    ] {
        assert_eq!(
            f.s3.handle(request(Method::GET, path, "", OWNER, Some(&f.reader)))
                .await
                .status(),
            200,
            "{path}"
        );
    }
    for path in [
        "/policy-source?list-type=2&prefix=forbidden%2F&delimiter=%2F&max-keys=5",
        "/policy-source?versions&prefix=forbidden%2F&delimiter=%2F&max-keys=1",
        "/policy-source?list-type=2&delimiter=%2F&max-keys=5",
        "/policy-source?list-type=2&prefix=allowed%2F&max-keys=5",
        "/policy-source?list-type=2&prefix=allowed%2F&delimiter=&max-keys=5",
        "/policy-source?list-type=2&prefix=allowed%2F&delimiter=%2F&max-keys=6",
        "/policy-source?list-type=2&prefix=allowed%2F&delimiter=%2F",
    ] {
        assert_eq!(
            f.s3.handle(request(Method::GET, path, "", OWNER, Some(&f.reader)))
                .await
                .status(),
            403,
            "{path}"
        );
    }
    // Defaults participate in conditions; absent prefix is an actual empty string.
    let defaults = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::policy-source","Condition":{"StringEquals":{"s3:prefix":""},"NumericEquals":{"s3:max-keys":"1000"}}}}"#;
    assert_eq!(f.policy("policy-source", defaults).await.status(), 204);
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source?list-type=2",
            "",
            OWNER,
            Some(&f.reader)
        ))
        .await
        .status(),
        200
    );
    // A prefix Deny must match supplied context even when IAM independently allows listing.
    let deny = r#"{"Statement":{"Effect":"Deny","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::policy-source","Condition":{"StringLike":{"s3:prefix":"forbidden/*"}}}}"#;
    assert_eq!(f.policy("policy-source", deny).await.status(), 204);
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source?list-type=2&prefix=forbidden%2F",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        403
    );
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source?list-type=2&prefix=allowed%2F",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        200
    );
}

async fn outsider_permissions(f: &Fixture, actions: &str) {
    let policy =
        format!(r#"{{"Statement":{{"Effect":"Allow","Action":{actions},"Resource":"*"}}}}"#);
    iam(
        &f.registry,
        OTHER,
        "PutUserPolicy",
        &[
            ("UserName", "outsider"),
            ("PolicyName", "read"),
            ("PolicyDocument", &policy),
        ],
    )
    .await;
}

#[tokio::test]
async fn cross_account_mutations_lists_and_copy_keep_destination_owner() {
    let f = Fixture::new().await;
    outsider_permissions(
        &f,
        r#"["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"]"#,
    )
    .await;
    for bucket in ["policy-source", "policy-dest"] {
        let grant = format!(
            r#"{{"Statement":{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::111111111111:user/outsider"}},"Action":["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:ListBucket"],"Resource":["arn:aws:s3:::{bucket}","arn:aws:s3:::{bucket}/*"]}}}}"#
        );
        assert_eq!(f.policy(bucket, &grant).await.status(), 204);
    }
    assert_eq!(
        f.s3.handle(request(
            Method::PUT,
            "/policy-source/foreign",
            "foreign-data",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        200
    );
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-source/foreign",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "foreign-data"
    );
    let list =
        f.s3.handle(request(
            Method::GET,
            "/policy-source?list-type=2&fetch-owner=true",
            "",
            OTHER,
            Some(&f.outsider),
        ))
        .await;
    assert_eq!(list.status(), 200);
    let listing = body(list).await;
    assert!(listing.contains("<Key>foreign</Key>"));
    assert!(listing.contains(&format!("<ID>{OWNER}</ID>")));
    let mut copy = request(
        Method::PUT,
        "/policy-dest/copied",
        "",
        OTHER,
        Some(&f.outsider),
    );
    copy.headers.insert(
        "x-amz-copy-source",
        HeaderValue::from_static("policy-source/foreign"),
    );
    assert_eq!(f.s3.handle(copy.clone()).await.status(), 200);
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-dest/copied",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "foreign-data"
    );
    assert_eq!(
        f.s3.handle(request(
            Method::DELETE,
            "/policy-source/foreign",
            "",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        204
    );
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/foreign",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        404
    );
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-dest/copied",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "foreign-data"
    );
    // Revoking source access cannot create another destination object.
    assert_eq!(
        f.s3.handle(request(
            Method::DELETE,
            "/policy-source?policy",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        204
    );
    copy.uri = "/policy-dest/denied-copy".parse().unwrap();
    assert_eq!(f.s3.handle(copy).await.status(), 403);
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-dest/denied-copy",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        404
    );
}

#[tokio::test]
async fn cross_account_resource_grant_requires_identity_allow() {
    let f = Fixture::new().await;
    let grant = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/outsider"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::policy-source/*"}}"#;
    assert_eq!(f.policy("policy-source", grant).await.status(), 204);
    assert_eq!(
        f.s3.handle(request(
            Method::PUT,
            "/policy-source/one-sided",
            "should-not-exist",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        403
    );
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/one-sided",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        404
    );
}

#[tokio::test]
async fn cross_account_policy_administration_is_forbidden_even_with_allow() {
    let f = Fixture::new().await;
    let grant = r#"{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/outsider"},"Action":["s3:GetBucketPolicy","s3:PutBucketPolicy","s3:DeleteBucketPolicy"],"Resource":"arn:aws:s3:::policy-source"}}"#;
    assert_eq!(f.policy("policy-source", grant).await.status(), 204);
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        assert_eq!(
            f.s3.handle(request(
                method.clone(),
                "/policy-source?policy",
                grant,
                OTHER,
                Some(&f.outsider)
            ))
            .await
            .status(),
            403
        );
    }
    outsider_permissions(
        &f,
        r#"["s3:GetBucketPolicy","s3:PutBucketPolicy","s3:DeleteBucketPolicy"]"#,
    )
    .await;
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let result =
            f.s3.handle(request(
                method,
                "/policy-source?policy",
                grant,
                OTHER,
                Some(&f.outsider),
            ))
            .await;
        assert_eq!(result.status(), 405);
        assert!(body(result).await.contains("<Code>MethodNotAllowed</Code>"));
    }
    let remaining =
        f.s3.handle(request(
            Method::GET,
            "/policy-source?policy",
            "",
            OWNER,
            Some(&f.admin),
        ))
        .await;
    assert_eq!(remaining.status(), 200);
    assert!(body(remaining).await.contains("s3:GetBucketPolicy"));
}

#[tokio::test]
async fn expected_bucket_owners_fail_closed_for_reads_and_copies() {
    let f = Fixture::new().await;
    let mut get = request(Method::GET, "/policy-source/key", "", OWNER, Some(&f.admin));
    get.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OTHER),
    );
    assert_eq!(f.s3.handle(get.clone()).await.status(), 403);
    get.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    assert_eq!(f.s3.handle(get).await.status(), 200);
    let mut copy = request(
        Method::PUT,
        "/policy-dest/owner-copy",
        "",
        OWNER,
        Some(&f.admin),
    );
    copy.headers.insert(
        "x-amz-copy-source",
        HeaderValue::from_static("policy-source/key"),
    );
    copy.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    copy.headers.insert(
        "x-amz-source-expected-bucket-owner",
        HeaderValue::from_static(OTHER),
    );
    assert_eq!(f.s3.handle(copy.clone()).await.status(), 403);
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-dest/owner-copy",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        404
    );
    copy.headers.insert(
        "x-amz-source-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    copy.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OTHER),
    );
    assert_eq!(f.s3.handle(copy.clone()).await.status(), 403);
    copy.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    assert_eq!(f.s3.handle(copy).await.status(), 200);
}

#[tokio::test]
async fn copies_between_distinct_bucket_owners_and_bucket_inventory_stay_scoped() {
    let f = Fixture::new().await;
    outsider_permissions(&f, r#""s3:*""#).await;
    let collision =
        f.s3.handle(request(
            Method::PUT,
            "/policy-source",
            "",
            OTHER,
            Some(&f.outsider),
        ))
        .await;
    assert_eq!(collision.status(), 409);
    assert!(body(collision)
        .await
        .contains("<Code>BucketAlreadyExists</Code>"));
    assert_eq!(
        f.s3.handle(request(
            Method::PUT,
            "/outsider-owned",
            "",
            OTHER,
            Some(&f.outsider)
        ))
        .await
        .status(),
        200
    );
    let inventory =
        f.s3.handle(request(Method::GET, "/", "", OTHER, Some(&f.outsider)))
            .await;
    assert_eq!(inventory.status(), 200);
    let inventory = body(inventory).await;
    assert!(inventory.contains("<Name>outsider-owned</Name>"));
    assert!(!inventory.contains("<Name>policy-source</Name>"));
    assert!(!inventory.contains("<Name>policy-dest</Name>"));
    for (bucket, action) in [
        ("policy-source", "s3:GetObject"),
        ("policy-dest", "s3:PutObject"),
    ] {
        let grant = format!(
            r#"{{"Statement":{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::111111111111:user/outsider"}},"Action":"{action}","Resource":"arn:aws:s3:::{bucket}/*"}}}}"#
        );
        assert_eq!(f.policy(bucket, &grant).await.status(), 204);
    }
    let mut copy = request(
        Method::PUT,
        "/outsider-owned/from-owner",
        "",
        OTHER,
        Some(&f.outsider),
    );
    copy.headers.insert(
        "x-amz-copy-source",
        HeaderValue::from_static("policy-source/key"),
    );
    copy.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OTHER),
    );
    copy.headers.insert(
        "x-amz-source-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    assert_eq!(f.s3.handle(copy).await.status(), 200);
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/outsider-owned/from-owner",
                "",
                OTHER,
                Some(&f.outsider)
            ))
            .await
        )
        .await,
        "original"
    );
    let mut back = request(
        Method::PUT,
        "/policy-dest/from-outsider",
        "",
        OTHER,
        Some(&f.outsider),
    );
    back.headers.insert(
        "x-amz-copy-source",
        HeaderValue::from_static("outsider-owned/from-owner"),
    );
    back.headers.insert(
        "x-amz-expected-bucket-owner",
        HeaderValue::from_static(OWNER),
    );
    back.headers.insert(
        "x-amz-source-expected-bucket-owner",
        HeaderValue::from_static(OTHER),
    );
    assert_eq!(f.s3.handle(back).await.status(), 200);
    assert_eq!(
        body(
            f.s3.handle(request(
                Method::GET,
                "/policy-dest/from-outsider",
                "",
                OWNER,
                Some(&f.admin)
            ))
            .await
        )
        .await,
        "original"
    );
}

#[tokio::test]
async fn strict_unmodeled_acl_upload_is_explicit_and_leaves_no_object() {
    let f = Fixture::new().await;
    let mut put = request(
        Method::PUT,
        "/policy-source/acl-object",
        "payload",
        OWNER,
        Some(&f.admin),
    );
    put.headers
        .insert("x-amz-acl", HeaderValue::from_static("private"));
    let response = f.s3.handle(put).await;
    assert_eq!(response.status(), 501);
    assert!(body(response).await.contains("<Code>NotImplemented</Code>"));
    assert_eq!(
        f.s3.handle(request(
            Method::GET,
            "/policy-source/acl-object",
            "",
            OWNER,
            Some(&f.admin)
        ))
        .await
        .status(),
        404
    );
}
