//! ARN parsing, construction, and resolution for cross-service calls.
//!
//! `arn:partition:service:region:account-id:resource` — `region` and `account-id` may be
//! empty for global services (IAM, S3). `resource` keeps any remaining `:`-separated tail
//! (e.g. `function:name`). See Requirement 2.

use std::sync::Arc;

use crate::error_mapping::AwsError;
use crate::registry::{ServiceName, ServiceRegistry};

/// A parsed Amazon Resource Name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arn {
    pub partition: String,
    pub service: String,
    pub region: String,
    pub account_id: String,
    pub resource: String,
}

/// A malformed ARN.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArnError {
    #[error("malformed ARN: {0}")]
    Malformed(String),
}

impl Arn {
    /// Parse `arn:partition:service:region:account:resource`. The resource segment retains
    /// any additional `:` (e.g. `function:my-fn`).
    pub fn parse(s: &str) -> Result<Arn, ArnError> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();
        if parts.len() < 6 || parts[0] != "arn" || parts[1].is_empty() || parts[2].is_empty() {
            return Err(ArnError::Malformed(s.to_string()));
        }
        Ok(Arn {
            partition: parts[1].to_string(),
            service: parts[2].to_ascii_lowercase(),
            region: parts[3].to_string(),
            account_id: parts[4].to_string(),
            resource: parts[5].to_string(),
        })
    }

    /// Build an ARN for a freshly created resource in the AWS-correct format.
    pub fn for_resource(service: &str, region: &str, account: &str, resource: &str) -> Arn {
        Arn {
            partition: "aws".to_string(),
            service: service.to_ascii_lowercase(),
            region: region.to_string(),
            account_id: account.to_string(),
            resource: resource.to_string(),
        }
    }

    /// Render back to the canonical `arn:…` string.
    pub fn to_arn_string(&self) -> String {
        format!(
            "arn:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.account_id, self.resource
        )
    }
}

/// Resolves an ARN to the canonical target service for dispatch, applying region/account
/// defaulting and rejecting unregistered services with a protocol-correct error.
pub struct ArnResolver {
    registry: Arc<ServiceRegistry>,
    default_account: String,
    default_region: String,
}

impl ArnResolver {
    pub fn new(
        registry: Arc<ServiceRegistry>,
        default_account: String,
        default_region: String,
    ) -> Self {
        ArnResolver {
            registry,
            default_account,
            default_region,
        }
    }

    /// Resolve an ARN to a registered service. Region/account defaulting for the resolved
    /// target is available via [`Self::effective_region`] / [`Self::effective_account`];
    /// `source_region` is accepted here for a uniform call site. An unregistered service is
    /// an `InvalidParameterValue` (400).
    pub fn resolve(
        &self,
        arn: &Arn,
        _source_region: Option<&str>,
    ) -> Result<ServiceName, AwsError> {
        let name = ServiceName::new(&arn.service);
        if self.registry.lookup(&name).is_none() {
            return Err(AwsError::new(
                "InvalidParameterValue",
                format!("ARN refers to an unregistered service: {}", arn.service),
                400,
            ));
        }
        Ok(name)
    }

    /// The effective region for an ARN: its own, else the source resource's, else the default.
    pub fn effective_region(&self, arn: &Arn, source_region: Option<&str>) -> String {
        if !arn.region.is_empty() {
            arn.region.clone()
        } else if let Some(r) = source_region.filter(|r| !r.is_empty()) {
            r.to_string()
        } else {
            self.default_region.clone()
        }
    }

    /// The effective account for an ARN: its own, else the Core default.
    pub fn effective_account(&self, arn: &Arn) -> String {
        if arn.account_id.is_empty() {
            self.default_account.clone()
        } else {
            arn.account_id.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> ArnResolver {
        ArnResolver::new(
            ServiceRegistry::with_known_services(),
            "000000000000".into(),
            "us-east-1".into(),
        )
    }

    #[test]
    fn parse_full_arn_keeps_resource_tail() {
        let arn = Arn::parse("arn:aws:lambda:us-east-1:000000000000:function:my-fn").unwrap();
        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "lambda");
        assert_eq!(arn.region, "us-east-1");
        assert_eq!(arn.account_id, "000000000000");
        assert_eq!(arn.resource, "function:my-fn");
    }

    #[test]
    fn parse_global_service_allows_empty_region_account() {
        let arn = Arn::parse("arn:aws:iam::000000000000:role/app").unwrap();
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.region, "");
        assert_eq!(arn.resource, "role/app");
    }

    #[test]
    fn parse_rejects_malformed() {
        assert!(Arn::parse("not-an-arn").is_err());
        assert!(Arn::parse("arn:aws").is_err());
        assert!(Arn::parse("arn::service:r:a:res").is_err());
    }

    #[test]
    fn round_trip_parse_for_resource() {
        let built = Arn::for_resource("sqs", "us-east-1", "000000000000", "my-queue");
        let parsed = Arn::parse(&built.to_arn_string()).unwrap();
        assert_eq!(built, parsed);
        assert_eq!(
            built.to_arn_string(),
            "arn:aws:sqs:us-east-1:000000000000:my-queue"
        );
    }

    #[test]
    fn resolve_known_service_succeeds() {
        let r = resolver();
        let arn = Arn::parse("arn:aws:sqs:us-east-1:000000000000:q").unwrap();
        assert_eq!(r.resolve(&arn, None).unwrap(), ServiceName::new("sqs"));
    }

    #[test]
    fn resolve_unregistered_service_is_400() {
        let r = resolver();
        let arn = Arn::parse("arn:aws:quantumdb:us-east-1:000000000000:thing").unwrap();
        let err = r.resolve(&arn, None).unwrap_err();
        assert_eq!(err.http_status, 400);
    }

    #[test]
    fn region_defaults_from_source_then_core() {
        let r = resolver();
        let global = Arn::parse("arn:aws:iam::000000000000:role/x").unwrap();
        assert_eq!(r.effective_region(&global, Some("eu-west-1")), "eu-west-1");
        assert_eq!(r.effective_region(&global, None), "us-east-1");
        let regional = Arn::parse("arn:aws:sqs:ap-south-1:000000000000:q").unwrap();
        assert_eq!(
            r.effective_region(&regional, Some("eu-west-1")),
            "ap-south-1"
        );
    }

    #[test]
    fn account_defaults_to_core() {
        let r = resolver();
        let arn = Arn {
            partition: "aws".into(),
            service: "sqs".into(),
            region: "us-east-1".into(),
            account_id: String::new(),
            resource: "q".into(),
        };
        assert_eq!(r.effective_account(&arn), "000000000000");
    }
}
