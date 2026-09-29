//! Cross-service identity attribution.
//!
//! Distinct from [`crate::integration::RequestIdentity`] (the authenticated SigV4 principal of
//! an external request): `CallerIdentity` is the *delegated* identity a cross-service hop
//! carries — an assumed execution role, a service principal, or the default development
//! identity. When IAM enforcement is enabled it is presented to the policy evaluator before
//! delivery; when disabled it is still propagated for audit/consistency and never blocks.
//! Secrets and tokens are never logged. See Requirement 3.

/// Identity attributed to a cross-service call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerIdentity {
    /// An assumed execution role (e.g. a Step Functions or Lambda execution role).
    AssumedRole {
        role_arn: String,
        session_name: String,
    },
    /// An AWS service principal performing an integration on its own behalf.
    ServicePrincipal { service: String },
    /// The default development identity (used when IAM enforcement is off).
    Default,
}

impl CallerIdentity {
    /// The access-key-equivalent principal string used for audit records. Never a secret.
    pub fn principal(&self) -> String {
        match self {
            CallerIdentity::AssumedRole {
                role_arn,
                session_name,
            } => {
                format!("{role_arn}/{session_name}")
            }
            CallerIdentity::ServicePrincipal { service } => format!("{service}.amazonaws.com"),
            CallerIdentity::Default => "default".to_string(),
        }
    }
}

/// Attaches a [`CallerIdentity`] to a cross-service call's headers so the target (and IAM
/// enforcement) sees a consistent caller. The header carries no secret material.
pub struct IdentityPropagator;

/// Internal header carrying the propagated cross-service principal (audit/enforcement only).
pub const PRINCIPAL_HEADER: &str = "x-localcloud-caller-principal";

impl IdentityPropagator {
    /// Attach the identity's principal to the outbound headers. Returns the principal string
    /// written, for correlation. Never writes secrets or tokens.
    pub fn attach(headers: &mut http::HeaderMap, identity: &CallerIdentity) -> String {
        let principal = identity.principal();
        if let Ok(value) = http::HeaderValue::from_str(&principal) {
            headers.insert(PRINCIPAL_HEADER, value);
        }
        principal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principals_render_per_kind() {
        assert_eq!(
            CallerIdentity::AssumedRole {
                role_arn: "arn:aws:iam::0:role/app".into(),
                session_name: "s1".into()
            }
            .principal(),
            "arn:aws:iam::0:role/app/s1"
        );
        assert_eq!(
            CallerIdentity::ServicePrincipal {
                service: "events".into()
            }
            .principal(),
            "events.amazonaws.com"
        );
        assert_eq!(CallerIdentity::Default.principal(), "default");
    }

    #[test]
    fn attach_writes_principal_header_no_secret() {
        let mut headers = http::HeaderMap::new();
        let identity = CallerIdentity::AssumedRole {
            role_arn: "arn:aws:iam::0:role/app".into(),
            session_name: "s".into(),
        };
        let written = IdentityPropagator::attach(&mut headers, &identity);
        assert_eq!(
            headers.get(PRINCIPAL_HEADER).unwrap(),
            "arn:aws:iam::0:role/app/s"
        );
        assert_eq!(written, "arn:aws:iam::0:role/app/s");
        // No secret/token material is present in any header.
        for (name, _) in headers.iter() {
            let n = name.as_str();
            assert!(!n.contains("secret") && !n.contains("token"));
        }
    }
}
