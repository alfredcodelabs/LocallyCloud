//! `AWS::S3::Bucket` → S3 `GetBucketNotificationConfiguration`.

use locallycloud_core::views::architecture::TopologyError;

use super::{deployed, reason, Context};
use crate::acl::identity::{types, Accept};
use crate::acl::reads::{self, Reply};
use crate::acl::stack::StackResource;
use crate::acl::xml;
use crate::domain::Finding;

/// Wire element, destination element, and the CloudFormation property it configures.
const NOTIFICATIONS: &[(&str, &[&str], &str)] = &[
    (
        "CloudFunctionConfiguration",
        &["CloudFunction", "LambdaFunctionArn"],
        "LambdaConfigurations",
    ),
    (
        "LambdaFunctionConfiguration",
        &["LambdaFunctionArn", "CloudFunction"],
        "LambdaConfigurations",
    ),
    ("QueueConfiguration", &["Queue"], "QueueConfigurations"),
    ("TopicConfiguration", &["Topic"], "TopicConfigurations"),
];

const DESTINATIONS: &[&str] = &[types::LAMBDA_FUNCTION, types::SQS_QUEUE, types::SNS_TOPIC];

pub(super) async fn extract(
    ctx: &Context<'_>,
    resource: &StackResource,
) -> Result<Vec<Finding>, TopologyError> {
    let id = resource.logical_id.as_str();
    const PROPERTY: &str = "NotificationConfiguration";
    if !valid_bucket_name(&resource.physical_id) {
        return Ok(vec![Finding::gap(id, PROPERTY, reason::READ_FAILED)]);
    }
    let path = format!("/{}?notification", resource.physical_id);
    let body = match ctx.reads.send(reads::rest_get("s3", &path)?).await? {
        Reply::Body(body) => body,
        Reply::Missing => return Ok(vec![Finding::gap(id, PROPERTY, reason::DRIFTED)]),
        Reply::Failed { .. } => return Ok(vec![Finding::gap(id, PROPERTY, reason::READ_FAILED)]),
    };
    let root = xml::parse(&body).ok_or_else(|| {
        TopologyError::Unprocessable(
            "S3 GetBucketNotificationConfiguration returned an unusable response".into(),
        )
    })?;
    let mut findings = Vec::new();
    for configuration in &root.children {
        let Some((_, fields, key)) = NOTIFICATIONS
            .iter()
            .find(|(element, _, _)| *element == configuration.name)
        else {
            continue;
        };
        let property = format!("{PROPERTY}.{key}");
        let destination = fields
            .iter()
            .find_map(|field| configuration.text_of(field))
            .unwrap_or_default();
        match ctx
            .identities
            .resolve(destination.trim(), Accept::Types(DESTINATIONS))
        {
            Some(to) => findings.push(Finding::configured(
                id,
                to,
                "notification",
                deployed(id, "GetBucketNotificationConfiguration", &property),
            )),
            None => findings.push(Finding::gap(id, property, reason::UNRESOLVED_DESTINATION)),
        }
    }
    Ok(findings)
}

/// Bucket names become a path segment; only the S3 naming alphabet is admitted.
fn valid_bucket_name(name: &str) -> bool {
    (3..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !name.contains("..")
}
