//! Security-relevant configuration facts declared in the processed template.
//!
//! Each fact is an enum value with the property path it came from. Policy documents,
//! environment values and other configuration never leave this module: only the
//! classification does. Facts describe what the deployed stack declares; they are not an
//! observation of runtime behavior.

use serde_json::Value;

use super::identity::types;
use super::template::{Resolver, TemplateView};
use crate::domain::{Fact, FactId, FactValue, Finding};

const BUCKET_POLICY: &str = "AWS::S3::BucketPolicy";
const QUEUE_POLICY: &str = "AWS::SQS::QueuePolicy";
const TOPIC_POLICY: &str = "AWS::SNS::TopicPolicy";
const EVENT_BUS_POLICY: &str = "AWS::Events::EventBusPolicy";
const IAM_ROLE: &str = "AWS::IAM::Role";
const IAM_POLICY: &str = "AWS::IAM::Policy";
const IAM_MANAGED_POLICY: &str = "AWS::IAM::ManagedPolicy";
const EVENT_INVOKE_CONFIG: &str = "AWS::Lambda::EventInvokeConfig";
const REST_STAGE: &str = "AWS::ApiGateway::Stage";
const USAGE_PLAN: &str = "AWS::ApiGateway::UsagePlan";
const HTTP_API: &str = "AWS::ApiGatewayV2::Api";
const HTTP_ROUTE: &str = "AWS::ApiGatewayV2::Route";
const HTTP_STAGE: &str = "AWS::ApiGatewayV2::Stage";
const SNS_SUBSCRIPTION: &str = "AWS::SNS::Subscription";
/// Environment variable names that usually hold credentials.
const SECRET_NAMES: &[&str] = &[
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "TOKEN",
    "PRIVATE_KEY",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "CREDENTIAL",
];
/// Name suffixes of variables that point to a secret instead of holding it.
const SECRET_REFERENCE_SUFFIXES: &[&str] = &["_ARN", "_ID", "_NAME", "_PATH"];
/// Write actions that only accept `Resource: "*"`, so a wildcard resource is not a gap.
const WILDCARD_ONLY_WRITES: &[&str] = &[
    "logs:CreateLogDelivery",
    "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery",
    "logs:PutResourcePolicy",
    "logs:DeleteResourcePolicy",
    "xray:PutTraceSegments",
    "xray:PutTelemetryRecords",
];
/// Properties through which a resource sends its failures to a queue.
const DEAD_LETTER_SOURCES: &[(&str, &[&str])] = &[
    (types::SQS_QUEUE, &["RedrivePolicy", "deadLetterTargetArn"]),
    (types::LAMBDA_FUNCTION, &["DeadLetterConfig", "TargetArn"]),
    (
        EVENT_INVOKE_CONFIG,
        &["DestinationConfig", "OnFailure", "Destination"],
    ),
    (
        types::EVENT_SOURCE_MAPPING,
        &["DestinationConfig", "OnFailure", "Destination"],
    ),
    (types::EVENT_RULE, &["Targets", "DeadLetterConfig", "Arn"]),
    (SNS_SUBSCRIPTION, &["RedrivePolicy", "deadLetterTargetArn"]),
];

struct Facts<'a, 't> {
    view: &'a TemplateView<'t>,
    resolver: &'a Resolver<'a>,
    logical_id: &'a str,
    found: Vec<Finding>,
}

impl<'t> Facts<'_, 't> {
    fn add(&mut self, id: FactId, value: FactValue, evidence: impl Into<String>) {
        self.found.push(Finding::Fact {
            target: self.logical_id.to_owned(),
            fact: Fact {
                id,
                value,
                evidence: evidence.into(),
            },
        });
    }

    fn own(&self, property: &str) -> String {
        format!("{}.Properties.{property} (template)", self.logical_id)
    }

    fn prop(&self, path: &[&str]) -> Option<&Value> {
        path.iter()
            .try_fold(self.view.properties(self.logical_id)?, |value, key| {
                value.get(key)
            })
    }

    fn text(&self, path: &[&str]) -> Option<String> {
        self.prop(path)
            .and_then(|value| self.resolver.literal(value))
    }

    /// Resources of `resource_type` whose `property` references this resource.
    fn referrers(&self, resource_type: &'static str, property: &str) -> Vec<(&'t str, &'t Value)> {
        self.view
            .of_type(resource_type)
            .filter(|(_, properties)| {
                properties
                    .get(property)
                    .is_some_and(|value| self.view.mentions(value, self.logical_id))
            })
            .collect()
    }
}

/// Facts of every declared resource whose type has a classifier.
pub(crate) fn findings(view: &TemplateView<'_>, resolver: &Resolver<'_>) -> Vec<Finding> {
    let mut found = Vec::new();
    for declaration in view.declarations() {
        let Some(classify) = declaration.resource_type.and_then(classifier) else {
            continue;
        };
        let mut facts = Facts {
            view,
            resolver,
            logical_id: declaration.logical_id,
            found: Vec::new(),
        };
        classify(&mut facts);
        found.append(&mut facts.found);
    }
    found
}

type Classifier = fn(&mut Facts<'_, '_>);

fn classifier(resource_type: &str) -> Option<Classifier> {
    Some(match resource_type {
        types::S3_BUCKET => bucket,
        types::SQS_QUEUE => queue,
        types::SNS_TOPIC => topic,
        types::LAMBDA_FUNCTION => function,
        types::STATE_MACHINE => state_machine,
        types::DYNAMODB_TABLE => table,
        types::DYNAMODB_GLOBAL_TABLE => global_table,
        types::REST_API => rest_api,
        HTTP_API => http_api,
        types::KINESIS_STREAM => stream,
        types::FIREHOSE_STREAM => delivery_stream,
        types::EVENT_BUS => event_bus,
        _ => return None,
    })
}

/// `true`/`false` as JSON or text; intrinsic functions are not evaluated.
fn flag(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) if text.eq_ignore_ascii_case("true") => Some(true),
        Value::String(text) if text.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn items(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

fn one_or_many(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(values)) => values.iter().collect(),
        Some(value) => vec![value],
        None => Vec::new(),
    }
}

fn statements(document: Option<&Value>) -> Vec<&Value> {
    one_or_many(document.and_then(|d| d.get("Statement")))
}

fn texts(value: Option<&Value>) -> Vec<&str> {
    one_or_many(value)
        .into_iter()
        .filter_map(Value::as_str)
        .collect()
}

fn denies_insecure_transport(statement: &Value) -> bool {
    statement.get("Effect").and_then(Value::as_str) == Some("Deny")
        && flag(
            statement
                .get("Condition")
                .and_then(|c| c.get("Bool"))
                .and_then(|b| b.get("aws:SecureTransport")),
        ) == Some(false)
}

/// An Allow statement for any principal without conditions.
fn allows_anyone(statement: &Value) -> bool {
    let anyone = match statement.get("Principal") {
        Some(Value::String(principal)) => principal == "*",
        Some(Value::Object(principal)) => texts(principal.get("AWS")).contains(&"*"),
        _ => false,
    };
    statement.get("Effect").and_then(Value::as_str) == Some("Allow")
        && anyone
        && statement.get("Condition").is_none()
}

/// TLS-only and resource-policy facts from the policies attached through `property`.
fn resource_policies(facts: &mut Facts<'_, '_>, policy_type: &'static str, property: &str) {
    let policies = facts.referrers(policy_type, property);
    let Some((first, _)) = policies.first() else {
        facts.add(
            FactId::TlsOnly,
            FactValue::NotDeclared,
            format!(
                "No {policy_type} references {} (template)",
                facts.logical_id
            ),
        );
        return;
    };
    let evidence = format!("{first}.Properties.PolicyDocument (template)");
    let all: Vec<&Value> = policies
        .iter()
        .flat_map(|(_, properties)| statements(properties.get("PolicyDocument")))
        .collect();
    let tls = if all.iter().any(|s| denies_insecure_transport(s)) {
        FactValue::Enforced
    } else {
        FactValue::NotDeclared
    };
    let exposure = if all.iter().any(|s| allows_anyone(s)) {
        FactValue::Public
    } else {
        FactValue::Restricted
    };
    facts.add(FactId::TlsOnly, tls, evidence.clone());
    facts.add(FactId::ResourcePolicy, exposure, evidence);
}

fn bucket(facts: &mut Facts<'_, '_>) {
    let algorithms: Vec<Option<String>> =
        items(facts.prop(&["BucketEncryption", "ServerSideEncryptionConfiguration"]))
            .iter()
            .map(|rule| {
                rule.get("ServerSideEncryptionByDefault")
                    .and_then(|d| d.get("SSEAlgorithm"))
                    .and_then(|a| facts.resolver.literal(a))
            })
            .collect();
    let encryption = match algorithms.first() {
        None => FactValue::ServiceManaged,
        Some(Some(algorithm)) if algorithm.starts_with("aws:kms") => FactValue::Kms,
        Some(Some(_)) => FactValue::ServiceManaged,
        Some(None) => FactValue::Unknown,
    };
    let evidence = if algorithms.is_empty() {
        format!(
            "{} declares no BucketEncryption; S3 applies SSE-S3 by default (template)",
            facts.logical_id
        )
    } else {
        facts.own("BucketEncryption")
    };
    facts.add(FactId::EncryptionAtRest, encryption, evidence);

    let block = facts.prop(&["PublicAccessBlockConfiguration"]);
    let flags: Vec<Option<bool>> = [
        "BlockPublicAcls",
        "BlockPublicPolicy",
        "IgnorePublicAcls",
        "RestrictPublicBuckets",
    ]
    .iter()
    .map(|name| flag(block.and_then(|b| b.get(*name))))
    .collect();
    let public_block = match block {
        None => FactValue::NotDeclared,
        Some(_) if flags.iter().all(|f| *f == Some(true)) => FactValue::Enabled,
        Some(_) if flags.contains(&Some(true)) => FactValue::Partial,
        Some(_) if flags.iter().any(Option::is_none) => FactValue::Unknown,
        Some(_) => FactValue::Disabled,
    };
    facts.add(
        FactId::PublicAccessBlock,
        public_block,
        facts.own("PublicAccessBlockConfiguration"),
    );

    let versioning = match facts
        .text(&["VersioningConfiguration", "Status"])
        .as_deref()
    {
        Some("Enabled") => FactValue::Enabled,
        Some("Suspended") => FactValue::Suspended,
        Some(_) => FactValue::Unknown,
        None if facts.prop(&["VersioningConfiguration"]).is_some() => FactValue::Unknown,
        None => FactValue::NotDeclared,
    };
    facts.add(
        FactId::Versioning,
        versioning,
        facts.own("VersioningConfiguration"),
    );
    resource_policies(facts, BUCKET_POLICY, "Bucket");
}

fn queue(facts: &mut Facts<'_, '_>) {
    let encryption = if facts.prop(&["KmsMasterKeyId"]).is_some() {
        FactValue::Kms
    } else {
        match flag(facts.prop(&["SqsManagedSseEnabled"])) {
            Some(false) => FactValue::Disabled,
            Some(true) => FactValue::ServiceManaged,
            None if facts.prop(&["SqsManagedSseEnabled"]).is_some() => FactValue::Unknown,
            // New queues use SSE-SQS unless it is disabled.
            None => FactValue::ServiceManaged,
        }
    };
    facts.add(
        FactId::EncryptionAtRest,
        encryption,
        facts.own("KmsMasterKeyId/SqsManagedSseEnabled"),
    );
    let redrive = facts.prop(&["RedrivePolicy"]);
    let parsed;
    let redrive = match redrive {
        Some(Value::String(text)) => {
            parsed = serde_json::from_str::<Value>(text).ok();
            parsed.as_ref()
        }
        other => other,
    };
    let (dead_letter, evidence) = if redrive.is_some_and(|r| r.get("deadLetterTargetArn").is_some())
    {
        (FactValue::Configured, facts.own("RedrivePolicy"))
    } else {
        dead_letter_source(facts).map_or_else(
            || (FactValue::NotDeclared, facts.own("RedrivePolicy")),
            |evidence| (FactValue::DeadLetterTarget, evidence),
        )
    };
    facts.add(FactId::DeadLetter, dead_letter, evidence);
    resource_policies(facts, QUEUE_POLICY, "Queues");
}

/// The first property that sends another resource's failures to this queue.
fn dead_letter_source(facts: &Facts<'_, '_>) -> Option<String> {
    DEAD_LETTER_SOURCES
        .iter()
        .find_map(|(resource_type, path)| {
            facts
                .view
                .of_type(resource_type)
                .filter(|(id, _)| *id != facts.logical_id)
                .find(|(_, properties)| {
                    values_at(properties, path)
                        .into_iter()
                        .any(|value| facts.view.mentions(value, facts.logical_id))
                })
                .map(|(id, _)| format!("{id}.Properties.{} (template)", path.join(".")))
        })
}

/// Values at `path`; a list on the way is read element by element, one level deep.
fn values_at<'v>(value: &'v Value, path: &[&str]) -> Vec<&'v Value> {
    let Some((key, rest)) = path.split_first() else {
        return vec![value];
    };
    let children: Vec<&Value> = match value {
        Value::Array(elements) => elements.iter().filter_map(|e| e.get(*key)).collect(),
        other => other.get(*key).into_iter().collect(),
    };
    children
        .into_iter()
        .flat_map(|child| values_at(child, rest))
        .collect()
}

fn topic(facts: &mut Facts<'_, '_>) {
    let encryption = if facts.prop(&["KmsMasterKeyId"]).is_some() {
        FactValue::Kms
    } else {
        FactValue::Disabled
    };
    facts.add(
        FactId::EncryptionAtRest,
        encryption,
        facts.own("KmsMasterKeyId"),
    );
    resource_policies(facts, TOPIC_POLICY, "Topics");
}

fn function(facts: &mut Facts<'_, '_>) {
    let (concurrency, evidence) = if facts.prop(&["ReservedConcurrentExecutions"]).is_some() {
        (
            FactValue::Limited,
            facts.own("ReservedConcurrentExecutions"),
        )
    } else {
        source_limited_concurrency(facts).map_or_else(
            || {
                (
                    FactValue::NotDeclared,
                    facts.own("ReservedConcurrentExecutions"),
                )
            },
            |evidence| (FactValue::Partial, evidence),
        )
    };
    facts.add(FactId::ReservedConcurrency, concurrency, evidence);

    let on_failure = facts
        .referrers(EVENT_INVOKE_CONFIG, "FunctionName")
        .into_iter()
        .find(|(_, p)| {
            p.get("DestinationConfig")
                .and_then(|d| d.get("OnFailure"))
                .is_some()
        })
        .map(|(id, _)| format!("{id}.Properties.DestinationConfig.OnFailure (template)"));
    let (dead_letter, evidence) = match (facts.prop(&["DeadLetterConfig", "TargetArn"]), on_failure)
    {
        (Some(_), _) => (FactValue::Configured, facts.own("DeadLetterConfig")),
        (None, Some(evidence)) => (FactValue::Configured, evidence),
        (None, None) => (FactValue::NotDeclared, facts.own("DeadLetterConfig")),
    };
    facts.add(FactId::DeadLetter, dead_letter, evidence);

    environment_secrets(facts);
    role_privilege(facts, "Role");
    log_retention(facts);
}

/// Evidence when every event source mapping of the function caps its concurrency.
/// That bounds only those sources, so it is partial, never a reserved limit.
fn source_limited_concurrency(facts: &Facts<'_, '_>) -> Option<String> {
    let mappings = facts.referrers(types::EVENT_SOURCE_MAPPING, "FunctionName");
    let capped = |properties: &Value| {
        properties
            .get("ScalingConfig")
            .and_then(|scaling| scaling.get("MaximumConcurrency"))
            .is_some()
    };
    if mappings.is_empty() || !mappings.iter().all(|(_, p)| capped(p)) {
        return None;
    }
    let ids: Vec<&str> = mappings.iter().map(|(id, _)| *id).collect();
    Some(format!(
        "{}.Properties.ScalingConfig.MaximumConcurrency bounds only those sources; {} declares no ReservedConcurrentExecutions (template)",
        ids.join(", "),
        facts.logical_id
    ))
}

/// Classifies environment variables without emitting their values.
fn environment_secrets(facts: &mut Facts<'_, '_>) {
    let variables = facts
        .prop(&["Environment", "Variables"])
        .and_then(Value::as_object);
    let mut resolved = Vec::new();
    let mut suspected = Vec::new();
    for (name, value) in variables.into_iter().flatten() {
        let Value::String(text) = value else {
            continue;
        };
        if text.contains("{{resolve:secretsmanager:") || text.contains("{{resolve:ssm-secure:") {
            resolved.push(name.as_str());
        } else if !text.is_empty() && !text.starts_with("arn:") {
            let upper = name.to_ascii_uppercase();
            let reference = SECRET_REFERENCE_SUFFIXES
                .iter()
                .any(|suffix| upper.ends_with(suffix));
            if !reference && SECRET_NAMES.iter().any(|marker| upper.contains(marker)) {
                suspected.push(name.as_str());
            }
        }
    }
    let (value, names) = match (resolved.is_empty(), suspected.is_empty()) {
        (false, _) => (FactValue::ResolvedSecret, resolved),
        (true, false) => (FactValue::Suspected, suspected),
        (true, true) => (FactValue::NoneDetected, Vec::new()),
    };
    let evidence = if names.is_empty() {
        facts.own("Environment.Variables")
    } else {
        format!(
            "{} variable names: {} (values not exported)",
            facts.own("Environment.Variables"),
            names.join(", ")
        )
    };
    facts.add(FactId::SecretsInEnvironment, value, evidence);
}

/// Classifies the permissions of the role named by `property`, from inline policies,
/// attached `AWS::IAM::Policy`/`ManagedPolicy` resources and managed policy ARNs.
fn role_privilege(facts: &mut Facts<'_, '_>, property: &str) {
    let Some(reference) = facts.prop(&[property]) else {
        return;
    };
    let roles: Vec<&str> = facts
        .view
        .referenced(reference)
        .into_iter()
        .filter(|id| facts.view.of_type(IAM_ROLE).any(|(role, _)| role == *id))
        .collect();
    let [role] = roles.as_slice() else {
        facts.add(
            FactId::RolePrivilege,
            FactValue::Unknown,
            format!(
                "{} names a role outside this stack (template)",
                facts.own(property)
            ),
        );
        return;
    };
    let role = *role;
    let mut documents: Vec<&Value> = Vec::new();
    let mut managed: Vec<String> = Vec::new();
    if let Some(properties) = facts.view.properties(role) {
        documents.extend(
            items(properties.get("Policies"))
                .iter()
                .filter_map(|p| p.get("PolicyDocument")),
        );
        managed.extend(
            items(properties.get("ManagedPolicyArns"))
                .iter()
                .filter_map(|arn| facts.resolver.literal(arn)),
        );
    }
    for policy_type in [IAM_POLICY, IAM_MANAGED_POLICY] {
        for (_, properties) in facts.view.of_type(policy_type) {
            if properties
                .get("Roles")
                .is_some_and(|roles| facts.view.mentions(roles, role))
            {
                documents.extend(properties.get("PolicyDocument"));
            }
        }
    }
    let allows: Vec<&Value> = documents
        .into_iter()
        .flat_map(|d| statements(Some(d)))
        .filter(|s| s.get("Effect").and_then(Value::as_str) == Some("Allow"))
        .collect();
    let wildcard_action = managed
        .iter()
        .any(|arn| arn.ends_with("/AdministratorAccess") || arn.ends_with("FullAccess"))
        || allows.iter().any(|s| {
            texts(s.get("Action"))
                .iter()
                .any(|a| *a == "*" || a.ends_with(":*"))
        });
    let on_any_resource: Vec<&str> = allows
        .iter()
        .filter(|s| texts(s.get("Resource")).contains(&"*"))
        .flat_map(|s| texts(s.get("Action")))
        .filter(|a| !is_read_action(a))
        .collect();
    let wildcard_resource = on_any_resource.iter().any(|a| !is_wildcard_only(a));
    let value = match (wildcard_action, wildcard_resource) {
        (true, _) => FactValue::WildcardAction,
        (false, true) => FactValue::WildcardResource,
        (false, false) => FactValue::Scoped,
    };
    let mut wildcard_only: Vec<&str> = on_any_resource
        .into_iter()
        .filter(|a| is_wildcard_only(a))
        .collect();
    wildcard_only.sort_unstable();
    wildcard_only.dedup();
    let evidence = if wildcard_only.is_empty() {
        format!("{role} policies (template; statements not exported)")
    } else {
        format!(
            "{role} policies (template; statements not exported); actions that only accept Resource \"*\": {}",
            wildcard_only.join(", ")
        )
    };
    facts.add(FactId::RolePrivilege, value, evidence);
}

/// IAM action names are case-insensitive.
fn is_wildcard_only(action: &str) -> bool {
    WILDCARD_ONLY_WRITES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(action))
}

fn is_read_action(action: &str) -> bool {
    let operation = action.split_once(':').map_or(action, |(_, op)| op);
    ["Describe", "Get", "List"]
        .iter()
        .any(|prefix| operation.starts_with(prefix))
}

fn log_retention(facts: &mut Facts<'_, '_>) {
    let configured = facts
        .prop(&["LoggingConfig", "LogGroup"])
        .map(|value| facts.view.referenced(value))
        .unwrap_or_default();
    // Lambda writes to LoggingConfig.LogGroup, or to /aws/lambda/<FunctionName> by default.
    let target_name = facts.text(&["LoggingConfig", "LogGroup"]).or_else(|| {
        facts
            .text(&["FunctionName"])
            .map(|name| format!("/aws/lambda/{name}"))
    });
    let group = facts
        .view
        .of_type(types::LOG_GROUP)
        .find(|(id, properties)| {
            configured.contains(id)
                || properties.get("LogGroupName").is_some_and(|name| {
                    facts.view.mentions(name, facts.logical_id)
                        || target_name.is_some() && facts.resolver.literal(name) == target_name
                })
        });
    let (value, evidence) = match group {
        Some((id, properties)) if properties.get("RetentionInDays").is_some() => (
            FactValue::Retained,
            format!("{id}.Properties.RetentionInDays (template)"),
        ),
        Some((id, _)) => (
            FactValue::NeverExpires,
            format!("{id} declares no RetentionInDays (template)"),
        ),
        None => (
            FactValue::NotDeclared,
            format!(
                "No log group of {} is declared; the default never expires (template)",
                facts.logical_id
            ),
        ),
    };
    facts.add(FactId::LogRetention, value, evidence);
}

fn state_machine(facts: &mut Facts<'_, '_>) {
    let logging = match facts.text(&["LoggingConfiguration", "Level"]).as_deref() {
        Some("ALL" | "ERROR" | "FATAL") => FactValue::Enabled,
        Some("OFF") => FactValue::Disabled,
        Some(_) => FactValue::Unknown,
        None => FactValue::NotDeclared,
    };
    facts.add(
        FactId::ExecutionLogging,
        logging,
        facts.own("LoggingConfiguration.Level"),
    );
    role_privilege(facts, "RoleArn");
}

fn recovery(specification: Option<&Value>) -> FactValue {
    match specification {
        None => FactValue::NotDeclared,
        Some(spec) => match flag(spec.get("PointInTimeRecoveryEnabled")) {
            Some(true) => FactValue::Enabled,
            Some(false) => FactValue::Disabled,
            None => FactValue::Unknown,
        },
    }
}

fn table_encryption(facts: &mut Facts<'_, '_>) {
    let customer_key = facts
        .text(&["SSESpecification", "SSEType"])
        .is_some_and(|t| t == "KMS")
        || facts
            .prop(&["SSESpecification", "KMSMasterKeyId"])
            .is_some();
    let value =
        if flag(facts.prop(&["SSESpecification", "SSEEnabled"])) == Some(true) && customer_key {
            FactValue::Kms
        } else {
            // DynamoDB always encrypts at rest with a key it owns.
            FactValue::ServiceManaged
        };
    facts.add(
        FactId::EncryptionAtRest,
        value,
        facts.own("SSESpecification"),
    );
}

fn table(facts: &mut Facts<'_, '_>) {
    let value = recovery(facts.prop(&["PointInTimeRecoverySpecification"]));
    facts.add(
        FactId::PointInTimeRecovery,
        value,
        facts.own("PointInTimeRecoverySpecification"),
    );
    table_encryption(facts);
}

fn global_table(facts: &mut Facts<'_, '_>) {
    let replicas: Vec<FactValue> = items(facts.prop(&["Replicas"]))
        .iter()
        .map(|replica| recovery(replica.get("PointInTimeRecoverySpecification")))
        .collect();
    let value = if replicas.is_empty() {
        FactValue::NotDeclared
    } else if replicas.iter().all(|v| *v == FactValue::Enabled) {
        FactValue::Enabled
    } else if replicas.contains(&FactValue::Enabled) {
        FactValue::Partial
    } else if replicas.contains(&FactValue::Unknown) {
        FactValue::Unknown
    } else {
        FactValue::NotDeclared
    };
    facts.add(
        FactId::PointInTimeRecovery,
        value,
        facts.own("Replicas[].PointInTimeRecoverySpecification"),
    );
    table_encryption(facts);
}

/// `AllMethods` when every route requires authorization, `Open` when none does.
fn authorization(open: usize, total: usize) -> FactValue {
    match (open, total) {
        (_, 0) => FactValue::NotDeclared,
        (0, _) => FactValue::AllMethods,
        (open, total) if open == total => FactValue::Open,
        _ => FactValue::SomeOpen,
    }
}

fn rest_api(facts: &mut Facts<'_, '_>) {
    let methods = facts.referrers(types::REST_METHOD, "RestApiId");
    let routes: Vec<_> = methods
        .iter()
        .filter(|(_, p)| p.get("HttpMethod").and_then(Value::as_str) != Some("OPTIONS"))
        .collect();
    let open = routes
        .iter()
        .filter(|(_, p)| {
            let kind = p.get("AuthorizationType").and_then(Value::as_str);
            matches!(kind, None | Some("NONE")) && flag(p.get("ApiKeyRequired")) != Some(true)
        })
        .count();
    facts.add(
        FactId::ApiAuthorization,
        authorization(open, routes.len()),
        format!(
            "{open} of {} AWS::ApiGateway::Method resources without authorization (template)",
            routes.len()
        ),
    );
    let stages = facts.referrers(REST_STAGE, "RestApiId");
    let stage_throttle = stages.iter().any(|(_, p)| {
        items(p.get("MethodSettings"))
            .iter()
            .any(|s| s.get("ThrottlingRateLimit").is_some())
    });
    let plan_throttle = facts.view.of_type(USAGE_PLAN).any(|(_, p)| {
        p.get("Throttle").is_some()
            && items(p.get("ApiStages")).iter().any(|s| {
                s.get("ApiId")
                    .is_some_and(|id| facts.view.mentions(id, facts.logical_id))
            })
    });
    facts.add(
        FactId::Throttling,
        if stage_throttle || plan_throttle {
            FactValue::Configured
        } else {
            FactValue::NotDeclared
        },
        "Stage MethodSettings and UsagePlan Throttle (template)",
    );
    let logs = stages.iter().any(|(_, p)| {
        p.get("AccessLogSetting")
            .and_then(|a| a.get("DestinationArn"))
            .is_some()
    });
    facts.add(
        FactId::AccessLogs,
        if logs {
            FactValue::Enabled
        } else {
            FactValue::NotDeclared
        },
        "Stage AccessLogSetting (template)",
    );
}

fn http_api(facts: &mut Facts<'_, '_>) {
    let routes = facts.referrers(HTTP_ROUTE, "ApiId");
    let open = routes
        .iter()
        .filter(|(_, p)| {
            matches!(
                p.get("AuthorizationType").and_then(Value::as_str),
                None | Some("NONE")
            )
        })
        .count();
    facts.add(
        FactId::ApiAuthorization,
        authorization(open, routes.len()),
        format!(
            "{open} of {} AWS::ApiGatewayV2::Route resources without authorization (template)",
            routes.len()
        ),
    );
    let stages = facts.referrers(HTTP_STAGE, "ApiId");
    let throttle = stages.iter().any(|(_, p)| {
        p.get("DefaultRouteSettings")
            .and_then(|s| s.get("ThrottlingRateLimit"))
            .is_some()
    });
    facts.add(
        FactId::Throttling,
        if throttle {
            FactValue::Configured
        } else {
            FactValue::NotDeclared
        },
        "Stage DefaultRouteSettings (template)",
    );
    let logs = stages.iter().any(|(_, p)| {
        p.get("AccessLogSettings")
            .and_then(|a| a.get("DestinationArn"))
            .is_some()
    });
    facts.add(
        FactId::AccessLogs,
        if logs {
            FactValue::Enabled
        } else {
            FactValue::NotDeclared
        },
        "Stage AccessLogSettings (template)",
    );
}

fn stream(facts: &mut Facts<'_, '_>) {
    let value = match facts
        .text(&["StreamEncryption", "EncryptionType"])
        .as_deref()
    {
        Some("KMS") => FactValue::Kms,
        Some(_) => FactValue::Unknown,
        None => FactValue::Disabled,
    };
    facts.add(
        FactId::EncryptionAtRest,
        value,
        facts.own("StreamEncryption"),
    );
}

fn delivery_stream(facts: &mut Facts<'_, '_>) {
    let value = match facts
        .text(&["DeliveryStreamEncryptionConfigurationInput", "KeyType"])
        .as_deref()
    {
        Some("CUSTOMER_MANAGED_CMK") => FactValue::Kms,
        Some("AWS_OWNED_CMK") => FactValue::ServiceManaged,
        Some(_) => FactValue::Unknown,
        None => FactValue::NotDeclared,
    };
    facts.add(
        FactId::EncryptionAtRest,
        value,
        facts.own("DeliveryStreamEncryptionConfigurationInput"),
    );
}

fn event_bus(facts: &mut Facts<'_, '_>) {
    let policies = facts.referrers(EVENT_BUS_POLICY, "EventBusName");
    let mut all: Vec<&Value> = policies
        .iter()
        .flat_map(|(_, p)| one_or_many(p.get("Statement")))
        .collect();
    all.extend(statements(facts.prop(&["Policy"])));
    let value = if all.is_empty() {
        FactValue::NotDeclared
    } else if all.iter().any(|s| allows_anyone(s)) {
        FactValue::Public
    } else {
        FactValue::Restricted
    };
    facts.add(
        FactId::ResourcePolicy,
        value,
        "EventBus Policy and EventBusPolicy resources (template)",
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn facts_of(template: Value) -> HashMap<(String, FactId), FactValue> {
        let parameters = HashMap::new();
        let resolver = Resolver {
            pseudo: HashMap::new(),
            parameters: &parameters,
            physical: HashMap::new(),
        };
        let view = TemplateView::new(&template).unwrap();
        findings(&view, &resolver)
            .into_iter()
            .filter_map(|finding| match finding {
                Finding::Fact { target, fact } => Some(((target, fact.id), fact.value)),
                _ => None,
            })
            .collect()
    }

    fn get(facts: &HashMap<(String, FactId), FactValue>, id: &str, fact: FactId) -> FactValue {
        facts[&(id.to_owned(), fact)]
    }

    #[test]
    fn classifies_bucket_controls_and_attached_policies() {
        let facts = facts_of(json!({"Resources": {
            "Ledger": {"Type": "AWS::S3::Bucket", "Properties": {
                "BucketEncryption": {"ServerSideEncryptionConfiguration": [
                    {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
                "PublicAccessBlockConfiguration": {"BlockPublicAcls": true, "BlockPublicPolicy": true,
                    "IgnorePublicAcls": "true", "RestrictPublicBuckets": true},
                "VersioningConfiguration": {"Status": "Enabled"}}},
            "LedgerPolicy": {"Type": "AWS::S3::BucketPolicy", "Properties": {
                "Bucket": {"Ref": "Ledger"},
                "PolicyDocument": {"Statement": [{"Sid": "DenyInsecureTransport", "Effect": "Deny",
                    "Principal": "*", "Action": "s3:*", "Resource": "*",
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}}},
            "Open": {"Type": "AWS::S3::Bucket", "Properties": {
                "PublicAccessBlockConfiguration": {"BlockPublicAcls": false, "BlockPublicPolicy": false,
                    "IgnorePublicAcls": false, "RestrictPublicBuckets": false}}},
            "OpenPolicy": {"Type": "AWS::S3::BucketPolicy", "Properties": {
                "Bucket": {"Ref": "Open"},
                "PolicyDocument": {"Statement": {"Effect": "Allow", "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject", "Resource": "*"}}}}
        }}));
        assert_eq!(
            get(&facts, "Ledger", FactId::EncryptionAtRest),
            FactValue::Kms
        );
        assert_eq!(
            get(&facts, "Ledger", FactId::PublicAccessBlock),
            FactValue::Enabled
        );
        assert_eq!(
            get(&facts, "Ledger", FactId::Versioning),
            FactValue::Enabled
        );
        assert_eq!(get(&facts, "Ledger", FactId::TlsOnly), FactValue::Enforced);
        assert_eq!(
            get(&facts, "Ledger", FactId::ResourcePolicy),
            FactValue::Restricted
        );
        assert_eq!(
            get(&facts, "Open", FactId::EncryptionAtRest),
            FactValue::ServiceManaged
        );
        assert_eq!(
            get(&facts, "Open", FactId::PublicAccessBlock),
            FactValue::Disabled
        );
        assert_eq!(
            get(&facts, "Open", FactId::Versioning),
            FactValue::NotDeclared
        );
        assert_eq!(get(&facts, "Open", FactId::TlsOnly), FactValue::NotDeclared);
        assert_eq!(
            get(&facts, "Open", FactId::ResourcePolicy),
            FactValue::Public
        );
    }

    #[test]
    fn classifies_function_role_environment_and_logs_without_values() {
        let template = json!({"Resources": {
            "Worker": {"Type": "AWS::Lambda::Function", "Properties": {
                "Role": {"Fn::GetAtt": ["WorkerRole", "Arn"]},
                "ReservedConcurrentExecutions": 5,
                "Environment": {"Variables": {
                    "DB_PASSWORD": "hunter2",
                    "LEDGER_BUCKET": {"Ref": "Ledger"},
                    "API_TOKEN": "{{resolve:secretsmanager:prod/token}}"}}}},
            "WorkerRole": {"Type": "AWS::IAM::Role", "Properties": {
                "Policies": [{"PolicyDocument": {"Statement": [
                    {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}]}}]}},
            "WorkerLogs": {"Type": "AWS::Logs::LogGroup", "Properties": {
                "LogGroupName": {"Fn::Sub": "/aws/lambda/${Worker}"}, "RetentionInDays": 30}},
            "Admin": {"Type": "AWS::Lambda::Function", "Properties": {
                "Role": {"Fn::GetAtt": ["AdminRole", "Arn"]},
                "DeadLetterConfig": {"TargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]}}}},
            "AdminRole": {"Type": "AWS::IAM::Role", "Properties": {}},
            "AdminPolicy": {"Type": "AWS::IAM::Policy", "Properties": {
                "Roles": [{"Ref": "AdminRole"}],
                "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "dynamodb:*", "Resource": "arn"}]}}},
            "External": {"Type": "AWS::Lambda::Function", "Properties": {"Role": "arn:aws:iam::1:role/x"}},
            "Ledger": {"Type": "AWS::S3::Bucket"},
            "Dlq": {"Type": "AWS::SQS::Queue"}
        }});
        let parameters = HashMap::new();
        let resolver = Resolver {
            pseudo: HashMap::new(),
            parameters: &parameters,
            physical: HashMap::new(),
        };
        let view = TemplateView::new(&template).unwrap();
        let all = findings(&view, &resolver);
        let text = format!("{all:?}");
        assert!(!text.contains("hunter2") && !text.contains("prod/token"));
        assert!(text.contains("API_TOKEN"));
        let facts = facts_of(template);
        assert_eq!(
            get(&facts, "Worker", FactId::SecretsInEnvironment),
            FactValue::ResolvedSecret
        );
        assert_eq!(
            get(&facts, "Worker", FactId::RolePrivilege),
            FactValue::WildcardResource
        );
        assert_eq!(
            get(&facts, "Worker", FactId::ReservedConcurrency),
            FactValue::Limited
        );
        assert_eq!(
            get(&facts, "Worker", FactId::LogRetention),
            FactValue::Retained
        );
        assert_eq!(
            get(&facts, "Worker", FactId::DeadLetter),
            FactValue::NotDeclared
        );
        assert_eq!(
            get(&facts, "Admin", FactId::RolePrivilege),
            FactValue::WildcardAction
        );
        assert_eq!(
            get(&facts, "Admin", FactId::DeadLetter),
            FactValue::Configured
        );
        assert_eq!(
            get(&facts, "Admin", FactId::SecretsInEnvironment),
            FactValue::NoneDetected
        );
        assert_eq!(
            get(&facts, "Admin", FactId::LogRetention),
            FactValue::NotDeclared
        );
        assert_eq!(
            get(&facts, "External", FactId::RolePrivilege),
            FactValue::Unknown
        );
    }

    #[test]
    fn classifies_queues_tables_apis_and_streams() {
        let facts = facts_of(json!({"Resources": {
            "Inbox": {"Type": "AWS::SQS::Queue", "Properties": {
                "RedrivePolicy": "{\"deadLetterTargetArn\":\"arn\",\"maxReceiveCount\":5}"}},
            "Plain": {"Type": "AWS::SQS::Queue", "Properties": {"SqsManagedSseEnabled": false}},
            "Ledger": {"Type": "AWS::DynamoDB::Table", "Properties": {
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": true},
                "SSESpecification": {"SSEEnabled": true, "SSEType": "KMS"}}},
            "Global": {"Type": "AWS::DynamoDB::GlobalTable", "Properties": {"Replicas": [
                {"PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": true}}, {}]}},
            "Api": {"Type": "AWS::ApiGateway::RestApi"},
            "Get": {"Type": "AWS::ApiGateway::Method", "Properties": {"RestApiId": {"Ref": "Api"},
                "HttpMethod": "GET", "AuthorizationType": "CUSTOM"}},
            "Post": {"Type": "AWS::ApiGateway::Method", "Properties": {"RestApiId": {"Ref": "Api"},
                "HttpMethod": "POST", "AuthorizationType": "NONE"}},
            "Cors": {"Type": "AWS::ApiGateway::Method", "Properties": {"RestApiId": {"Ref": "Api"},
                "HttpMethod": "OPTIONS"}},
            "Stage": {"Type": "AWS::ApiGateway::Stage", "Properties": {"RestApiId": {"Ref": "Api"},
                "AccessLogSetting": {"DestinationArn": "arn"},
                "MethodSettings": [{"ThrottlingRateLimit": 10}]}},
            "Events": {"Type": "AWS::Kinesis::Stream", "Properties": {
                "StreamEncryption": {"EncryptionType": "KMS", "KeyId": "alias/aws/kinesis"}}},
            "Process": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
                "LoggingConfiguration": {"Level": "OFF"}}}
        }}));
        assert_eq!(
            get(&facts, "Inbox", FactId::DeadLetter),
            FactValue::Configured
        );
        assert_eq!(
            get(&facts, "Inbox", FactId::EncryptionAtRest),
            FactValue::ServiceManaged
        );
        assert_eq!(
            get(&facts, "Plain", FactId::EncryptionAtRest),
            FactValue::Disabled
        );
        assert_eq!(
            get(&facts, "Plain", FactId::DeadLetter),
            FactValue::NotDeclared
        );
        assert_eq!(
            get(&facts, "Ledger", FactId::PointInTimeRecovery),
            FactValue::Enabled
        );
        assert_eq!(
            get(&facts, "Ledger", FactId::EncryptionAtRest),
            FactValue::Kms
        );
        assert_eq!(
            get(&facts, "Global", FactId::PointInTimeRecovery),
            FactValue::Partial
        );
        assert_eq!(
            get(&facts, "Api", FactId::ApiAuthorization),
            FactValue::SomeOpen
        );
        assert_eq!(
            get(&facts, "Api", FactId::Throttling),
            FactValue::Configured
        );
        assert_eq!(get(&facts, "Api", FactId::AccessLogs), FactValue::Enabled);
        assert_eq!(
            get(&facts, "Events", FactId::EncryptionAtRest),
            FactValue::Kms
        );
        assert_eq!(
            get(&facts, "Process", FactId::ExecutionLogging),
            FactValue::Disabled
        );
        assert!(!facts.contains_key(&("Process".to_owned(), FactId::RolePrivilege)));
    }

    #[test]
    fn resolves_literal_log_groups_dead_letter_targets_and_source_limits() {
        let facts = facts_of(json!({"Resources": {
            "Ledger": {"Type": "AWS::Lambda::Function", "Properties": {
                "LoggingConfig": {"LogGroup": "cwl-grp-ledger-dev"}}},
            "LedgerLogs": {"Type": "AWS::Logs::LogGroup", "Properties": {
                "LogGroupName": "cwl-grp-ledger-dev", "RetentionInDays": 365}},
            "Named": {"Type": "AWS::Lambda::Function", "Properties": {"FunctionName": "named-fn"}},
            "NamedLogs": {"Type": "AWS::Logs::LogGroup", "Properties": {
                "LogGroupName": "/aws/lambda/named-fn"}},
            "Other": {"Type": "AWS::Lambda::Function", "Properties": {
                "LoggingConfig": {"LogGroup": "someone-else"}}},
            "Ingest": {"Type": "AWS::Lambda::Function"},
            "IngestMapping": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
                "FunctionName": {"Ref": "Ingest"}, "EventSourceArn": {"Fn::GetAtt": ["Inbox", "Arn"]},
                "ScalingConfig": {"MaximumConcurrency": 2}}},
            "Mixed": {"Type": "AWS::Lambda::Function"},
            "MixedCapped": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
                "FunctionName": {"Ref": "Mixed"}, "ScalingConfig": {"MaximumConcurrency": 2}}},
            "MixedOpen": {"Type": "AWS::Lambda::EventSourceMapping", "Properties": {
                "FunctionName": {"Ref": "Mixed"}}},
            "Inbox": {"Type": "AWS::SQS::Queue", "Properties": {
                "RedrivePolicy": {"deadLetterTargetArn": {"Fn::GetAtt": ["InboxDlq", "Arn"]}}}},
            "InboxDlq": {"Type": "AWS::SQS::Queue"},
            "Rule": {"Type": "AWS::Events::Rule", "Properties": {"Targets": [
                {"Id": "t", "Arn": {"Fn::GetAtt": ["Target", "Arn"]},
                 "DeadLetterConfig": {"Arn": {"Fn::GetAtt": ["RuleDlq", "Arn"]}}}]}},
            "Target": {"Type": "AWS::SQS::Queue"},
            "RuleDlq": {"Type": "AWS::SQS::Queue"}
        }}));
        assert_eq!(
            get(&facts, "Ledger", FactId::LogRetention),
            FactValue::Retained
        );
        assert_eq!(
            get(&facts, "Named", FactId::LogRetention),
            FactValue::NeverExpires
        );
        assert_eq!(
            get(&facts, "Other", FactId::LogRetention),
            FactValue::NotDeclared
        );
        assert_eq!(
            get(&facts, "Ingest", FactId::ReservedConcurrency),
            FactValue::Partial
        );
        assert_eq!(
            get(&facts, "Mixed", FactId::ReservedConcurrency),
            FactValue::NotDeclared
        );
        assert_eq!(
            get(&facts, "InboxDlq", FactId::DeadLetter),
            FactValue::DeadLetterTarget
        );
        assert_eq!(
            get(&facts, "RuleDlq", FactId::DeadLetter),
            FactValue::DeadLetterTarget
        );
        assert_eq!(
            get(&facts, "Inbox", FactId::DeadLetter),
            FactValue::Configured
        );
        assert_eq!(
            get(&facts, "Target", FactId::DeadLetter),
            FactValue::NotDeclared
        );
    }

    #[test]
    fn ignores_wildcard_only_actions_and_secret_references() {
        let facts = facts_of(json!({"Resources": {
            "Flow": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
                "RoleArn": {"Fn::GetAtt": ["FlowRole", "Arn"]}}},
            "FlowRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{"PolicyDocument": {
                "Statement": [
                    {"Effect": "Allow", "Resource": "*", "Action": [
                        "logs:CreateLogDelivery", "logs:putresourcepolicy", "xray:PutTraceSegments",
                        "xray:GetSamplingRules", "lakeformation:GetDataAccess"]},
                    {"Effect": "Allow", "Resource": "arn:aws:s3:::raw/*", "Action": "s3:PutObject"}]}}]}},
            "Loose": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
                "RoleArn": {"Fn::GetAtt": ["LooseRole", "Arn"]}}},
            "LooseRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{"PolicyDocument": {
                "Statement": {"Effect": "Allow", "Resource": "*",
                    "Action": ["logs:CreateLogDelivery", "s3:PutObject"]}}}]}},
            "Sftp": {"Type": "AWS::Lambda::Function", "Properties": {"Environment": {"Variables": {
                "SFTP_VAULT_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x",
                "SFTP_CONNECTION_SECRET_ID": "sftp/connection",
                "VAULT_SECRETS_PATH": "kv/sftp",
                "SECRET_LOOKUP": "arn:aws:ssm:us-east-1:1:parameter/x"}}}},
            "Leaky": {"Type": "AWS::Lambda::Function", "Properties": {"Environment": {"Variables": {
                "SFTP_VAULT_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:1:secret:x",
                "CLIENT_SECRET": "plain"}}}}
        }}));
        assert_eq!(
            get(&facts, "Flow", FactId::RolePrivilege),
            FactValue::Scoped
        );
        assert_eq!(
            get(&facts, "Loose", FactId::RolePrivilege),
            FactValue::WildcardResource
        );
        assert_eq!(
            get(&facts, "Sftp", FactId::SecretsInEnvironment),
            FactValue::NoneDetected
        );
        assert_eq!(
            get(&facts, "Leaky", FactId::SecretsInEnvironment),
            FactValue::Suspected
        );
    }

    #[test]
    fn names_wildcard_only_actions_in_the_evidence() {
        let template = json!({"Resources": {
            "Flow": {"Type": "AWS::StepFunctions::StateMachine", "Properties": {
                "RoleArn": {"Fn::GetAtt": ["FlowRole", "Arn"]}}},
            "FlowRole": {"Type": "AWS::IAM::Role", "Properties": {"Policies": [{"PolicyDocument": {
                "Statement": {"Effect": "Allow", "Resource": "*",
                    "Action": ["logs:PutResourcePolicy", "logs:CreateLogDelivery"]}}}]}}
        }});
        let parameters = HashMap::new();
        let resolver = Resolver {
            pseudo: HashMap::new(),
            parameters: &parameters,
            physical: HashMap::new(),
        };
        let view = TemplateView::new(&template).unwrap();
        let evidence = findings(&view, &resolver)
            .into_iter()
            .find_map(|finding| match finding {
                Finding::Fact { fact, .. } if fact.id == FactId::RolePrivilege => {
                    Some(fact.evidence)
                }
                _ => None,
            })
            .unwrap();
        assert!(evidence.ends_with("logs:CreateLogDelivery, logs:PutResourcePolicy"));
    }
}
