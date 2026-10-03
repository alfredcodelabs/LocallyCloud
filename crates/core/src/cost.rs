//! First-order cost estimation from metered usage.
//!
//! Maps request counts to an estimated USD cost using approximate **us-east-1**
//! per-million-request prices. This is a deliberate first-order estimate by request count:
//! it answers "what order of magnitude would this traffic cost on AWS?", not a billing-grade
//! figure. Dimensions that require real execution (Lambda duration × memory, S3 stored bytes,
//! DynamoDB read/write split) are refined as those capabilities land; until then they are
//! approximated per request and labelled as such.

use crate::metering::ServiceMetrics;

/// Approximate us-east-1 price per **one million requests**, in USD. Request-type-dependent
/// services (DynamoDB read/write, S3 PUT/GET) use a blended first-order rate.
fn price_per_million(service: &str) -> Option<f64> {
    let rate = match service {
        "lambda" => 0.20,
        "sqs" => 0.40,
        "sns" => 0.50,
        "dynamodb" | "streams.dynamodb" => 1.25, // blended read/write, approximate
        "apigateway" | "execute-api" => 1.00,
        "events" => 1.00,
        "states" => 25.0, // per million state transitions, approximate
        "kinesis" => 0.015,
        "s3" => 0.50, // blended request price, approximate
        _ => return None,
    };
    Some(rate)
}

/// Estimated cost for one service.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceCost {
    pub service: String,
    pub requests: u64,
    pub estimated_usd: f64,
    /// `false` when no price is modelled for the service (cost reported as 0, not hidden).
    pub priced: bool,
}

/// The full cost report for a metering snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct CostReport {
    pub services: Vec<ServiceCost>,
    pub total_usd: f64,
}

/// Estimate cost from a metering snapshot. Approximate, by request count (see module docs).
pub fn estimate(metrics: &[ServiceMetrics]) -> CostReport {
    let mut services = Vec::with_capacity(metrics.len());
    let mut total = 0.0;
    for m in metrics {
        let (usd, priced) = match price_per_million(&m.service) {
            Some(rate) => ((m.requests as f64) / 1_000_000.0 * rate, true),
            None => (0.0, false),
        };
        total += usd;
        services.push(ServiceCost {
            service: m.service.clone(),
            requests: m.requests,
            estimated_usd: usd,
            priced,
        });
    }
    CostReport {
        services,
        total_usd: total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(service: &str, requests: u64) -> ServiceMetrics {
        ServiceMetrics {
            service: service.into(),
            requests,
            bytes_in: 0,
        }
    }

    #[test]
    fn priced_service_scales_with_requests() {
        let report = estimate(&[metric("sqs", 1_000_000)]);
        assert_eq!(report.services[0].estimated_usd, 0.40);
        assert!(report.services[0].priced);
        assert_eq!(report.total_usd, 0.40);
    }

    #[test]
    fn unpriced_service_reports_zero_not_hidden() {
        let report = estimate(&[metric("quantumdb", 5_000_000)]);
        assert_eq!(report.services[0].estimated_usd, 0.0);
        assert!(!report.services[0].priced);
    }

    #[test]
    fn total_sums_across_services() {
        let report = estimate(&[metric("sqs", 1_000_000), metric("sns", 1_000_000)]);
        assert!((report.total_usd - 0.90).abs() < 1e-9);
    }
}
