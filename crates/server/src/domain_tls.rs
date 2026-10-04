//! Connect API Gateway domain ownership to ACM's internal certificate material.
use std::sync::Arc;

pub(crate) struct DomainTls {
    pub account: String,
    pub gateway: locallycloud_apigateway::service::ApiGatewayWafBinding,
    pub certificates: Arc<dyn locallycloud_acm::AcmAssociationApi>,
}

#[async_trait::async_trait]
impl locallycloud_core::tls::TlsIdentityResolver for DomainTls {
    async fn resolve(&self, server_name: &str) -> Option<locallycloud_core::tls::TlsIdentity> {
        let (region, arn) = self
            .gateway
            .tls_certificate_arn(&self.account, server_name)
            .await?;
        let identity = self
            .certificates
            .tls_identity(&self.account, &region, &arn, server_name)
            .ok()?;
        Some(locallycloud_core::tls::TlsIdentity {
            certificate_der: identity.certificate_der,
            private_key_der: identity.private_key_der,
        })
    }
}
