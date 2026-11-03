//! Matches identifiers found in deployed configuration against the stack inventory.
//!
//! Each resource type contributes the identities AWS uses for it (name, ARN, URL). A value
//! resolves only when exactly one accepted resource carries it; anything else is a gap.

use std::collections::HashMap;

use locallycloud_core::views::architecture::Scope;

use super::stack::StackResource;

pub(crate) mod types {
    pub const LAMBDA_FUNCTION: &str = "AWS::Lambda::Function";
    pub const EVENT_SOURCE_MAPPING: &str = "AWS::Lambda::EventSourceMapping";
    pub const SQS_QUEUE: &str = "AWS::SQS::Queue";
    pub const SNS_TOPIC: &str = "AWS::SNS::Topic";
    pub const DYNAMODB_TABLE: &str = "AWS::DynamoDB::Table";
    pub const DYNAMODB_GLOBAL_TABLE: &str = "AWS::DynamoDB::GlobalTable";
    pub const KINESIS_STREAM: &str = "AWS::Kinesis::Stream";
    pub const FIREHOSE_STREAM: &str = "AWS::KinesisFirehose::DeliveryStream";
    pub const EVENT_BUS: &str = "AWS::Events::EventBus";
    pub const EVENT_RULE: &str = "AWS::Events::Rule";
    pub const STATE_MACHINE: &str = "AWS::StepFunctions::StateMachine";
    pub const REST_API: &str = "AWS::ApiGateway::RestApi";
    pub const REST_METHOD: &str = "AWS::ApiGateway::Method";
    pub const S3_BUCKET: &str = "AWS::S3::Bucket";
    pub const LOG_GROUP: &str = "AWS::Logs::LogGroup";
}

/// Which resource types a reference may land on.
#[derive(Clone, Copy)]
pub(crate) enum Accept<'a> {
    Any,
    Types(&'a [&'a str]),
}

impl Accept<'_> {
    fn admits(self, resource_type: &str) -> bool {
        match self {
            Accept::Any => true,
            Accept::Types(types) => types.contains(&resource_type),
        }
    }
}

pub(crate) struct Identities {
    region: String,
    entries: Vec<(String, String)>,
    aliases: HashMap<String, Vec<usize>>,
}

impl Identities {
    pub(crate) fn new(scope: &Scope, resources: &[StackResource]) -> Self {
        let mut index = Self {
            region: scope.region.clone(),
            entries: Vec::new(),
            aliases: HashMap::new(),
        };
        for resource in resources.iter().filter(|r| !r.physical_id.is_empty()) {
            let position = index.entries.len();
            index
                .entries
                .push((resource.logical_id.clone(), resource.resource_type.clone()));
            for alias in aliases(scope, &resource.resource_type, &resource.physical_id) {
                let positions = index
                    .aliases
                    .entry(canonical(&alias, &scope.region))
                    .or_default();
                if !positions.contains(&position) {
                    positions.push(position);
                }
            }
        }
        index
    }

    /// The logical ID of the single accepted resource carrying `value`.
    pub(crate) fn resolve(&self, value: &str, accept: Accept<'_>) -> Option<&str> {
        let positions = self.aliases.get(&canonical(value, &self.region))?;
        let mut matches = positions
            .iter()
            .filter_map(|&i| self.entries.get(i))
            .filter(|(_, resource_type)| accept.admits(resource_type));
        let (logical_id, _) = matches.next()?;
        matches.next().is_none().then_some(logical_id.as_str())
    }
}

/// The identities AWS uses for one deployed resource, by type.
fn aliases(scope: &Scope, resource_type: &str, physical_id: &str) -> Vec<String> {
    let arn = |service: &str, resource: &str| {
        format!(
            "arn:aws:{service}:{}:{}:{resource}",
            scope.region, scope.account
        )
    };
    let named = |service: &str, prefix: &str| -> Vec<String> {
        match physical_id.strip_prefix("arn:") {
            Some(_) => {
                let name = physical_id
                    .split_once(prefix)
                    .map_or(physical_id, |(_, name)| name);
                vec![physical_id.to_owned(), name.to_owned()]
            }
            None => vec![
                physical_id.to_owned(),
                arn(service, &format!("{prefix}{physical_id}")),
            ],
        }
    };
    match resource_type {
        types::LAMBDA_FUNCTION => named("lambda", "function:"),
        types::DYNAMODB_TABLE | types::DYNAMODB_GLOBAL_TABLE => named("dynamodb", "table/"),
        types::KINESIS_STREAM => named("kinesis", "stream/"),
        types::FIREHOSE_STREAM => named("firehose", "deliverystream/"),
        types::EVENT_BUS => named("events", "event-bus/"),
        types::STATE_MACHINE => named("states", "stateMachine:"),
        types::LOG_GROUP => {
            let mut all = named("logs", "log-group:");
            all.push(arn("logs", &format!("log-group:{physical_id}:*")));
            all
        }
        types::S3_BUCKET => vec![
            physical_id.to_owned(),
            format!("arn:aws:s3:::{physical_id}"),
        ],
        // Queue URLs canonicalize to their ARN; topics and others are ARNs or opaque IDs.
        _ => vec![physical_id.to_owned()],
    }
}

/// One spelling per identity: queue URLs become ARNs, qualified function ARNs and table
/// stream ARNs drop their suffix.
pub(crate) fn canonical(value: &str, region: &str) -> String {
    if let Some(arn) = queue_url_arn(value, region) {
        return arn;
    }
    let parts: Vec<&str> = value.splitn(8, ':').collect();
    match parts.as_slice() {
        ["arn", partition, "lambda", region, account, "function", name, _qualifier] => {
            format!("arn:{partition}:lambda:{region}:{account}:function:{name}")
        }
        ["arn", _, "dynamodb", ..] => match value.split_once("/stream/") {
            Some((table, _)) => table.to_owned(),
            None => value.to_owned(),
        },
        _ => value.to_owned(),
    }
}

/// `https://host/<account>/<name>` → `arn:aws:sqs:<region>:<account>:<name>`.
fn queue_url_arn(value: &str, region: &str) -> Option<String> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    let (_, path) = rest.split_once('/')?;
    let mut segments = path.trim_end_matches('/').split('/');
    let (account, name) = (segments.next()?, segments.next()?);
    let valid = segments.next().is_none()
        && account.len() == 12
        && account.bytes().all(|b| b.is_ascii_digit())
        && !name.is_empty();
    valid.then(|| format!("arn:aws:sqs:{region}:{account}:{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resource(logical: &str, resource_type: &str, physical: &str) -> StackResource {
        StackResource {
            logical_id: logical.into(),
            resource_type: resource_type.into(),
            physical_id: physical.into(),
            status: "CREATE_COMPLETE".into(),
        }
    }

    fn index() -> Identities {
        let scope = Scope {
            account: "000000000000".into(),
            region: "us-east-1".into(),
        };
        Identities::new(
            &scope,
            &[
                resource("Worker", types::LAMBDA_FUNCTION, "worker"),
                resource(
                    "Inbox",
                    types::SQS_QUEUE,
                    "http://sqs.us-east-1.localhost:4566/000000000000/inbox",
                ),
                resource("Ledger", types::DYNAMODB_TABLE, "ledger"),
                resource("Same", types::S3_BUCKET, "shared"),
                resource("Other", types::KINESIS_STREAM, "shared"),
                resource("Pending", types::SQS_QUEUE, ""),
            ],
        )
    }

    #[test]
    fn resolves_every_spelling_of_one_identity() {
        let index = index();
        let lambda = Accept::Types(&[types::LAMBDA_FUNCTION]);
        for value in [
            "worker",
            "arn:aws:lambda:us-east-1:000000000000:function:worker",
            "arn:aws:lambda:us-east-1:000000000000:function:worker:live",
        ] {
            assert_eq!(index.resolve(value, lambda), Some("Worker"), "{value}");
        }
        assert_eq!(
            index.resolve("arn:aws:sqs:us-east-1:000000000000:inbox", Accept::Any),
            Some("Inbox")
        );
        assert_eq!(
            index.resolve("http://localhost:4566/000000000000/inbox", Accept::Any),
            Some("Inbox")
        );
        assert_eq!(
            index.resolve(
                "arn:aws:dynamodb:us-east-1:000000000000:table/ledger/stream/2026",
                Accept::Any
            ),
            Some("Ledger")
        );
    }

    #[test]
    fn refuses_ambiguous_external_and_wrongly_typed_values() {
        let index = index();
        assert_eq!(index.resolve("shared", Accept::Any), None);
        assert_eq!(
            index.resolve("shared", Accept::Types(&[types::S3_BUCKET])),
            Some("Same")
        );
        assert_eq!(
            index.resolve("worker", Accept::Types(&[types::SQS_QUEUE])),
            None
        );
        assert_eq!(
            index.resolve(
                "arn:aws:lambda:us-east-1:999999999999:function:worker",
                Accept::Any
            ),
            None
        );
        assert_eq!(index.resolve("", Accept::Any), None);
    }
}
