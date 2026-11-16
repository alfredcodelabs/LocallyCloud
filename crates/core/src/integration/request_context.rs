//! IAM context derived from Core's verified connection metadata.
use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::handler::ServiceRequest;

/// Core strips client-supplied values for these reserved headers before native dispatch.
/// Forward access sessions redact network properties rather than inheriting a client's hop.
pub fn verified_request_context(request: &ServiceRequest) -> BTreeMap<String, Vec<String>> {
    let mut context =
        BTreeMap::from([("aws:requestedregion".into(), vec![request.region.clone()])]);
    if request
        .headers
        .get("x-locallycloud-verified-internal-scope")
        .is_some_and(|value| value == "1")
    {
        return context;
    }
    if let Some(transport) = request
        .headers
        .get("x-locallycloud-verified-secure-transport")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "true" | "false"))
    {
        context.insert("aws:securetransport".into(), vec![transport.into()]);
    }
    if let Some(ip) = request
        .headers
        .get("x-locallycloud-trusted-peer-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok())
    {
        context.insert("aws:sourceip".into(), vec![ip.to_string()]);
    }
    context
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ServiceRequest {
        ServiceRequest {
            method: http::Method::POST,
            uri: "/".parse().unwrap(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
            region: "us-east-1".into(),
            account_id: "000000000000".into(),
            request_id: "request-context".into(),
        }
    }

    #[test]
    fn network_context_uses_valid_attested_values_and_ignores_forwarding_claims() {
        let mut request = request();
        request
            .headers
            .insert("x-forwarded-proto", "https".parse().unwrap());
        request
            .headers
            .insert("x-forwarded-for", "198.51.100.1".parse().unwrap());
        request
            .headers
            .insert("forwarded", "for=198.51.100.1;proto=https".parse().unwrap());
        assert_eq!(verified_request_context(&request).len(), 1);
        request.headers.insert(
            "x-locallycloud-verified-secure-transport",
            "false".parse().unwrap(),
        );
        request.headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "127.0.0.1".parse().unwrap(),
        );
        let context = verified_request_context(&request);
        assert_eq!(context["aws:securetransport"], ["false"]);
        assert_eq!(context["aws:sourceip"], ["127.0.0.1"]);
        request.headers.insert(
            "x-locallycloud-verified-secure-transport",
            "true".parse().unwrap(),
        );
        request.headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "2001:db8::1".parse().unwrap(),
        );
        let context = verified_request_context(&request);
        assert_eq!(context["aws:securetransport"], ["true"]);
        assert_eq!(context["aws:sourceip"], ["2001:db8::1"]);
        request.headers.insert(
            "x-locallycloud-verified-internal-scope",
            "1".parse().unwrap(),
        );
        assert_eq!(verified_request_context(&request).len(), 1);
    }

    #[test]
    fn malformed_reserved_context_is_omitted() {
        let mut request = request();
        request.headers.insert(
            "x-locallycloud-verified-secure-transport",
            "TRUE".parse().unwrap(),
        );
        request.headers.insert(
            "x-locallycloud-trusted-peer-ip",
            "127.0.0.1:4566".parse().unwrap(),
        );
        assert_eq!(verified_request_context(&request).len(), 1);
    }
}
