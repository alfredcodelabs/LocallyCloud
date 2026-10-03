//! Status reporting and the built-in dashboard.
//!
//! A read-only view over the [`ServiceRegistry`](crate::registry::ServiceRegistry) (the single
//! source of truth for which services are enabled and how they are handled). `status_json`
//! powers both programmatic checks and the embedded dashboard. Its HTML and JavaScript are
//! served from the binary without a build step or framework.

use serde_json::json;

use crate::cost::CostReport;
use crate::metering::ServiceMetrics;
use crate::registry::{Disposition, ServiceRegistry};

/// The built-in dashboard page, polling `/_locallycloud/status`.
pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
pub const DASHBOARD_JS: &str = include_str!("dashboard.js");
pub const DASHBOARD_I18N: &str = include_str!("dashboard-i18n.js");
pub const DASHBOARD_CSS: &str = include_str!("dashboard.css");

/// One embedded SVG sprite; related API namespaces share the same symbol.
pub const SERVICE_ICONS_SVG: &str = include_str!("icons/sprite.svg");

/// Return the sprite symbol ID for a registered service.
pub fn service_icon(service: &str) -> Option<&'static str> {
    match service {
        "dynamodb" | "streams.dynamodb" => Some("dynamodb"),
        "s3" => Some("s3"),
        "lambda" => Some("lambda"),
        "logs" | "monitoring" => Some("logs"),
        "states" => Some("states"),
        "sqs" => Some("sqs"),
        "acm" => Some("acm"),
        "apigateway" | "apigatewayv2" | "execute-api" => Some("apigateway"),
        "athena" => Some("athena"),
        "cloudformation" => Some("cloudformation"),
        "cloudfront" => Some("cloudfront"),
        "cloudtrail" => Some("cloudtrail"),
        "cognito-idp" => Some("cognito-idp"),
        "ec2" => Some("ec2"),
        "ecr" => Some("ecr"),
        "ecs" => Some("ecs"),
        "elasticloadbalancing" => Some("elasticloadbalancing"),
        "events" | "pipes" | "scheduler" | "schemas" => Some("events"),
        "firehose" => Some("firehose"),
        "glue" => Some("glue"),
        "iam" | "sts" => Some("iam"),
        "kinesis" => Some("kinesis"),
        "kms" => Some("kms"),
        "rds" | "rds-data" => Some("rds"),
        "route53"
        | "arc-region-switch"
        | "route53-recovery-cluster"
        | "route53-recovery-control-config" => Some("route53"),
        "secretsmanager" => Some("secretsmanager"),
        "sns" => Some("sns"),
        "ssm" => Some("ssm"),
        "wafv2" => Some("wafv2"),
        "xray" => Some("xray"),
        _ => None,
    }
}

/// Build the status document: product/version/readiness, every registered service with its
/// protocol and disposition (`Native` = handled in-process, `Proxied` = forwarded), plus
/// metered request counts and a first-order estimated cost (see [`crate::cost`]).
pub fn status_json(
    registry: &ServiceRegistry,
    metrics: &[ServiceMetrics],
    cost: &CostReport,
    ready: bool,
    version: &str,
) -> String {
    let statuses = registry.statuses();
    let native = statuses
        .iter()
        .filter(|s| s.disposition == Disposition::Native)
        .count();
    let services: Vec<_> = statuses
        .iter()
        .map(|s| {
            let requests = metrics
                .iter()
                .find(|m| m.service == s.name)
                .map(|m| m.requests)
                .unwrap_or(0);
            let estimated_usd = cost
                .services
                .iter()
                .find(|c| c.service == s.name)
                .map(|c| c.estimated_usd)
                .unwrap_or(0.0);
            json!({
                "name": s.name,
                "icon": service_icon(s.name.as_str()).map(|symbol| format!("/_locallycloud/icons.svg#{symbol}")),
                "protocol": s.protocol.as_str(),
                "disposition": s.disposition.as_str(),
                "requests": requests,
                "estimatedUsd": estimated_usd,
            })
        })
        .collect();
    json!({
        "product": "locallycloud",
        "version": version,
        "ready": ready,
        "serviceCount": services.len(),
        "nativeCount": native,
        "totalRequests": metrics.iter().map(|m| m.requests).sum::<u64>(),
        "estimatedCostUsd": cost.total_usd,
        "costNote": "first-order estimate by request count, approximate us-east-1 pricing",
        "services": services,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::estimate;
    use crate::handler::{NativeHandler, ServiceRequest};
    use crate::metering::ServiceMetrics;
    use crate::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
    use axum::body::Body;
    use axum::response::Response;
    use std::sync::Arc;

    struct TestHandler;

    #[async_trait::async_trait]
    impl NativeHandler for TestHandler {
        async fn handle(&self, _request: ServiceRequest) -> Response {
            Response::new(Body::empty())
        }
    }

    #[test]
    fn status_lists_services_metrics_and_cost() {
        let reg = ServiceRegistry::with_known_services();
        reg.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(TestHandler),
        );
        let metrics = vec![ServiceMetrics {
            service: "sqs".into(),
            requests: 1_000_000,
            bytes_in: 0,
        }];
        let cost = estimate(&metrics);
        let doc: serde_json::Value =
            serde_json::from_str(&status_json(&reg, &metrics, &cost, true, "0.1.0")).unwrap();
        assert_eq!(doc["product"], "locallycloud");
        assert_eq!(doc["ready"], true);
        assert_eq!(doc["totalRequests"], 1_000_000);
        assert!((doc["estimatedCostUsd"].as_f64().unwrap() - 0.40).abs() < 1e-9);
        let s3 = doc["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "s3")
            .unwrap();
        assert_eq!(s3["disposition"], "Native");
        assert_eq!(s3["protocol"], "REST-XML");
        assert_eq!(s3["icon"], "/_locallycloud/icons.svg#s3");
        assert_eq!(service_icon("logs"), service_icon("monitoring"));
        assert!(service_icon("unknown-service").is_none());
        let sqs = doc["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "sqs")
            .unwrap();
        assert_eq!(sqs["requests"], 1_000_000);
    }

    #[test]
    fn dashboard_html_is_embedded() {
        assert!(DASHBOARD_HTML.contains("locallycloud"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/dashboard.js"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/dashboard.css"));
        assert!(!DASHBOARD_HTML.contains("<style>"));
        assert!(DASHBOARD_CSS.contains(".brand-logo"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/brand/icon.svg"));
        assert!(DASHBOARD_JS.contains("/_locallycloud/status"));
    }
}
