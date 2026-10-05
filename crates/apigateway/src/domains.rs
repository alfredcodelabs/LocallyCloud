//! Certificate association and the active regional endpoints owned by API Gateway.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use locallycloud_acm::{AcmAssociationApi, AssociationDecision};

use crate::error::ApiGwError;

#[derive(Clone)]
pub(crate) struct DomainBinding {
    pub account: String,
    pub region: String,
    pub name: String,
    pub certificate_arn: String,
    pub target: String,
    pub zone: String,
}

#[derive(Default)]
pub(crate) struct DomainBindings {
    acm: Option<Arc<dyn AcmAssociationApi>>,
    active: Mutex<HashMap<String, DomainBinding>>,
    defer_releases: bool,
}

pub(crate) fn canonical(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

impl DomainBindings {
    pub fn with_acm(acm: Arc<dyn AcmAssociationApi>) -> Self {
        Self {
            acm: Some(acm),
            active: Mutex::default(),
            defer_releases: false,
        }
    }

    pub fn prepare(
        &self,
        account: &str,
        region: &str,
        name: &str,
        arn: &str,
        target: Option<&str>,
    ) -> Result<DomainBinding, ApiGwError> {
        if name.contains('*') {
            return Err(ApiGwError::BadRequest(
                "Wildcard custom domains are not supported by the local TLS listener".into(),
            ));
        }
        let acm = self.acm.as_ref().ok_or_else(|| {
            ApiGwError::BadRequest("ACM-backed custom domain TLS is unavailable".into())
        })?;
        // Validate usable private material too; eligibility metadata alone cannot serve TLS.
        acm.tls_identity(account, region, arn, name).map_err(|decision| match decision {
            AssociationDecision::StateUnavailable => ApiGwError::Internal("ACM certificate state is unavailable".into()),
            _ => ApiGwError::BadRequest("The regional ACM certificate is missing, unusable or does not cover the domain name".into()),
        })?;
        let zone = regional_zone(region).ok_or_else(|| {
            ApiGwError::BadRequest(
                "The API Gateway regional hosted zone is not supported in this region".into(),
            )
        })?;
        Ok(DomainBinding {
            account: account.into(),
            region: region.into(),
            name: canonical(name),
            certificate_arn: arn.into(),
            target: target.map(str::to_string).unwrap_or_else(|| {
                format!(
                    "d-{}.execute-api.{region}.amazonaws.com",
                    crate::store::gen_id()
                )
            }),
            zone: zone.into(),
        })
    }

    pub fn publish(&self, binding: DomainBinding) -> Result<(), ApiGwError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| ApiGwError::Internal("Custom domain bindings are unavailable".into()))?;
        if active
            .get(&binding.name)
            .is_some_and(|old| old.account != binding.account || old.region != binding.region)
        {
            return Err(ApiGwError::Conflict(
                "A custom domain cannot share this local TLS endpoint across accounts or regions"
                    .into(),
            ));
        }
        let acm = self.acm.as_ref().ok_or_else(|| {
            ApiGwError::Internal("ACM custom domain binding is unavailable".into())
        })?;
        let consumer = format!(
            "arn:aws:apigateway:{}::/domainnames/{}",
            binding.region, binding.name
        );
        acm.acquire(
            &binding.account,
            &binding.region,
            &binding.certificate_arn,
            &binding.name,
            &consumer,
        )
        .map_err(association_error)?;
        if let Some(old) = active
            .get(&binding.name)
            .filter(|old| !self.defer_releases && old.certificate_arn != binding.certificate_arn)
        {
            if let Err(error) =
                acm.release(&old.account, &old.region, &old.certificate_arn, &consumer)
            {
                let _ = acm.release(
                    &binding.account,
                    &binding.region,
                    &binding.certificate_arn,
                    &consumer,
                );
                return Err(association_error(error));
            }
        }
        active.insert(binding.name.clone(), binding);
        Ok(())
    }

    pub fn remove(&self, account: &str, region: &str, name: &str) -> Result<(), ApiGwError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| ApiGwError::Internal("Custom domain bindings are unavailable".into()))?;
        let name = canonical(name);
        if let Some(binding) = active
            .get(&name)
            .filter(|entry| entry.account == account && entry.region == region)
        {
            let consumer = format!("arn:aws:apigateway:{region}::/domainnames/{name}");
            if !self.defer_releases {
                self.acm
                    .as_ref()
                    .ok_or_else(|| {
                        ApiGwError::Internal("ACM custom domain binding is unavailable".into())
                    })?
                    .release(account, region, &binding.certificate_arn, &consumer)
                    .map_err(association_error)?;
            }
            active.remove(&name);
        }
        Ok(())
    }

    pub fn certificate(&self, account: &str, hostname: &str) -> Option<(String, String)> {
        let active = self.active.lock().ok()?;
        let binding = active.get(&canonical(hostname))?;
        (binding.account == account)
            .then(|| (binding.region.clone(), binding.certificate_arn.clone()))
    }

    pub fn alias_registered(&self, account: &str, target: &str, zone: &str) -> bool {
        let target = canonical(target);
        let zone = zone.strip_prefix("/hostedzone/").unwrap_or(zone);
        self.active.lock().is_ok_and(|active| {
            active.values().any(|binding| {
                binding.account == account
                    && canonical(&binding.target) == target
                    && binding.zone == zone
            })
        })
    }
}

fn association_error(decision: AssociationDecision) -> ApiGwError {
    match decision {
        AssociationDecision::StateUnavailable => {
            ApiGwError::Internal("ACM certificate state is unavailable".into())
        }
        _ => ApiGwError::BadRequest(
            "The regional ACM certificate is missing, unusable or does not cover the domain name"
                .into(),
        ),
    }
}

// AWS General Reference, API Gateway regional data-plane hosted zones (2026-10-03).
fn regional_zone(region: &str) -> Option<&'static str> {
    Some(match region {
        "us-east-1" => "Z1UJRXOUMOOFQ8",
        "us-east-2" => "ZOJJZC49E0EPZ",
        "us-west-1" => "Z2MUQ32089INYE",
        "us-west-2" => "Z2OJLYMUO9EFXC",
        "af-south-1" => "Z2DHW2332DAMTN",
        "ap-east-1" => "Z3FD1VL90ND7K5",
        "ap-south-2" => "Z0853509Q1135NJ66RUH",
        "ap-southeast-3" => "Z10132843TYUYSLUG4HA3",
        "ap-southeast-5" => "Z0314042F0KBUTZ3X5HF",
        "ap-southeast-4" => "Z092189423Y7RJK61311D",
        "ap-south-1" => "Z3VO1THU9YC4UR",
        "ap-northeast-3" => "Z22ILHG95FLSZ2",
        "ap-northeast-2" => "Z20JF4UZKIW1U8",
        "ap-southeast-1" => "ZL327KTPIQFUL",
        "ap-southeast-2" => "Z2RPCDW04V8134",
        "ap-east-2" => "Z02909591O7FG9Q56HWB1",
        "ap-southeast-7" => "Z048508712PZLK5NKG8R0",
        "ap-northeast-1" => "Z1YSHQZHG15GKL",
        "ca-central-1" => "Z19DQILCV0OWEC",
        "ca-west-1" => "Z04745493436AWVTG1OQY",
        "eu-central-1" => "Z1U9ULNL0V5AJ3",
        "eu-west-1" => "ZLY8HYME6SFDD",
        "eu-west-2" => "ZJ5UAJN8Y3Z2Q",
        "eu-south-1" => "Z3BT4WSQ9TDYZV",
        "eu-west-3" => "Z3KY65QIEKYHQQ",
        "eu-south-2" => "Z02499852UI5HEQ5JVWX3",
        "eu-north-1" => "Z3UWIKFBOOGXPP",
        "eu-central-2" => "Z09222482MK253X48U76H",
        "il-central-1" => "Z07264553HBI44N5X2CKP",
        "mx-central-1" => "Z00020171WIGL5M88SHRM",
        "me-south-1" => "Z20ZBPC0SS8806",
        "me-central-1" => "Z08780021BKYYY8U0YHTV",
        "sa-east-1" => "ZCMLWB8V5SYIT",
        "us-gov-east-1" => "Z3SE9ATJYCRCZJ",
        "us-gov-west-1" => "Z1K6XKP9SAGWDV",
        _ => return None,
    })
}

pub(crate) fn rest_binding(
    ctx: &crate::v1::Ctx<'_>,
    domain: &serde_json::Value,
    target: Option<&str>,
) -> Result<DomainBinding, ApiGwError> {
    if domain.pointer("/endpointConfiguration/types") != Some(&serde_json::json!(["REGIONAL"])) {
        return Err(ApiGwError::BadRequest(
            "Only REGIONAL public custom domains support local TLS; EDGE is not implemented".into(),
        ));
    }
    supported_tls(domain, domain.get("securityPolicy"))?;
    let arn = domain
        .get("regionalCertificateArn")
        .and_then(serde_json::Value::as_str)
        .filter(|arn| !arn.is_empty())
        .ok_or_else(|| {
            ApiGwError::BadRequest(
                "regionalCertificateArn is required for a REGIONAL custom domain".into(),
            )
        })?;
    let name = domain
        .get("domainName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    ctx.domains
        .prepare(ctx.account, ctx.region, name, arn, target)
}

pub(crate) fn http_binding(
    ctx: &crate::v1::Ctx<'_>,
    domain: &serde_json::Value,
    target: Option<&str>,
) -> Result<DomainBinding, ApiGwError> {
    let configs = domain
        .get("domainNameConfigurations")
        .and_then(serde_json::Value::as_array)
        .filter(|configs| configs.len() == 1)
        .ok_or_else(|| {
            ApiGwError::BadRequest(
                "Exactly one REGIONAL domainNameConfiguration is required".into(),
            )
        })?;
    let config = &configs[0];
    if !config.is_object()
        || config
            .get("endpointType")
            .is_some_and(|kind| kind.as_str() != Some("REGIONAL"))
    {
        return Err(ApiGwError::BadRequest(
            "Only REGIONAL public custom domains support local TLS".into(),
        ));
    }
    supported_tls(domain, config.get("securityPolicy"))?;
    let arn = config
        .get("certificateArn")
        .and_then(serde_json::Value::as_str)
        .filter(|arn| !arn.is_empty())
        .ok_or_else(|| {
            ApiGwError::BadRequest("certificateArn is required for a REGIONAL custom domain".into())
        })?;
    let name = domain
        .get("domainName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    ctx.domains
        .prepare(ctx.account, ctx.region, name, arn, target)
}

fn supported_tls(
    domain: &serde_json::Value,
    policy: Option<&serde_json::Value>,
) -> Result<(), ApiGwError> {
    if domain
        .get("mutualTlsAuthentication")
        .is_some_and(|config| !config.is_null())
    {
        return Err(ApiGwError::BadRequest(
            "Mutual TLS custom domains are not implemented".into(),
        ));
    }
    if policy.is_some_and(|policy| policy.as_str() != Some("TLS_1_2")) {
        return Err(ApiGwError::BadRequest(
            "Only TLS_1_2 security policy is supported".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture_bindings() -> DomainBindings {
    struct CertificateFixture;
    impl AcmAssociationApi for CertificateFixture {
        fn preflight(
            &self,
            account: &str,
            region: &str,
            arn: &str,
            _: &str,
        ) -> AssociationDecision {
            if arn == format!("arn:aws:acm:{region}:{account}:certificate/test") {
                AssociationDecision::Eligible
            } else {
                AssociationDecision::NotFound
            }
        }
        fn acquire(
            &self,
            account: &str,
            region: &str,
            arn: &str,
            name: &str,
            _: &str,
        ) -> Result<(), AssociationDecision> {
            match self.preflight(account, region, arn, name) {
                AssociationDecision::Eligible => Ok(()),
                error => Err(error),
            }
        }
        fn release(&self, _: &str, _: &str, _: &str, _: &str) -> Result<(), AssociationDecision> {
            Ok(())
        }
        fn tls_identity(
            &self,
            account: &str,
            region: &str,
            arn: &str,
            name: &str,
        ) -> Result<locallycloud_acm::AcmTlsIdentity, AssociationDecision> {
            match self.preflight(account, region, arn, name) {
                AssociationDecision::Eligible => Ok(locallycloud_acm::AcmTlsIdentity {
                    certificate_der: vec![0],
                    private_key_der: vec![0].into(),
                }),
                error => Err(error),
            }
        }
    }
    DomainBindings::with_acm(Arc::new(CertificateFixture))
}

/// Compensate ACM associations when a staged configuration is cancelled or fails to commit.
pub(crate) struct DomainTransaction<'a> {
    original: &'a DomainBindings,
    pub staged: DomainBindings,
    committed: bool,
}
impl DomainBindings {
    pub(crate) fn transaction(&self) -> Result<DomainTransaction<'_>, ApiGwError> {
        let active = self
            .active
            .lock()
            .map_err(|_| ApiGwError::Internal("Custom domain bindings are unavailable".into()))?
            .clone();
        Ok(DomainTransaction {
            original: self,
            staged: Self {
                acm: self.acm.clone(),
                active: Mutex::new(active),
                defer_releases: true,
            },
            committed: false,
        })
    }
}
impl DomainTransaction<'_> {
    pub(crate) fn commit(mut self) -> Result<(), ApiGwError> {
        let mut original =
            self.original.active.lock().map_err(|_| {
                ApiGwError::Internal("Custom domain bindings are unavailable".into())
            })?;
        let staged =
            self.staged.active.lock().map_err(|_| {
                ApiGwError::Internal("Custom domain bindings are unavailable".into())
            })?;
        let retired: Vec<_> = original
            .iter()
            .filter(|(name, old)| {
                !staged
                    .get(*name)
                    .is_some_and(|new| new.certificate_arn == old.certificate_arn)
            })
            .map(|(_, binding)| binding.clone())
            .collect();
        *original = staged.clone();
        self.committed = true;
        drop(original);
        drop(staged);
        // Retain the old certificate lease until the new configuration/binding is confirmed.
        if let Some(acm) = &self.original.acm {
            for binding in retired {
                let consumer = format!(
                    "arn:aws:apigateway:{}::/domainnames/{}",
                    binding.region, binding.name
                );
                if acm
                    .release(
                        &binding.account,
                        &binding.region,
                        &binding.certificate_arn,
                        &consumer,
                    )
                    .is_err()
                {
                    tracing::error!("API Gateway retired certificate lease cleanup failed; restart rebuilds current associations");
                }
            }
        }
        Ok(())
    }
}
impl Drop for DomainTransaction<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let Some(acm) = &self.original.acm else {
            return;
        };
        let Ok(original) = self.original.active.lock() else {
            tracing::error!("API Gateway certificate rollback unavailable");
            return;
        };
        let Ok(staged) = self.staged.active.lock() else {
            tracing::error!("API Gateway staged certificate rollback unavailable");
            return;
        };
        for (name, binding) in staged.iter() {
            if original
                .get(name)
                .is_some_and(|old| old.certificate_arn == binding.certificate_arn)
            {
                continue;
            }
            let consumer = format!(
                "arn:aws:apigateway:{}::/domainnames/{}",
                binding.region, binding.name
            );
            if acm
                .release(
                    &binding.account,
                    &binding.region,
                    &binding.certificate_arn,
                    &consumer,
                )
                .is_err()
            {
                tracing::error!("API Gateway staged certificate association rollback failed");
            }
        }
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Default)]
    struct Leases(Mutex<BTreeMap<String, BTreeSet<String>>>);
    impl AcmAssociationApi for Leases {
        fn preflight(&self, _: &str, _: &str, _: &str, _: &str) -> AssociationDecision {
            AssociationDecision::Eligible
        }
        fn tls_identity(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<locallycloud_acm::AcmTlsIdentity, AssociationDecision> {
            Err(AssociationDecision::NotFound)
        }
        fn acquire(
            &self,
            _: &str,
            _: &str,
            arn: &str,
            _: &str,
            consumer: &str,
        ) -> Result<(), AssociationDecision> {
            self.0
                .lock()
                .unwrap()
                .entry(arn.into())
                .or_default()
                .insert(consumer.into());
            Ok(())
        }
        fn release(
            &self,
            _: &str,
            _: &str,
            arn: &str,
            consumer: &str,
        ) -> Result<(), AssociationDecision> {
            if let Some(leases) = self.0.lock().unwrap().get_mut(arn) {
                leases.remove(consumer);
            }
            Ok(())
        }
    }
    #[test]
    fn old_certificate_is_reserved_until_binding_commit_and_staged_lease_rolls_back() {
        let leases = Arc::new(Leases::default());
        let bindings = DomainBindings::with_acm(leases.clone());
        let binding = |arn: &str| DomainBinding {
            account: "account".into(),
            region: "us-east-1".into(),
            name: "orders.example.test".into(),
            certificate_arn: arn.into(),
            target: "regional-target".into(),
            zone: "regional-zone".into(),
        };
        let held = |arn: &str| {
            leases
                .0
                .lock()
                .unwrap()
                .get(arn)
                .is_some_and(|leases| !leases.is_empty())
        };
        bindings.publish(binding("old")).unwrap();
        {
            let transaction = bindings.transaction().unwrap();
            transaction
                .staged
                .remove("account", "us-east-1", "orders.example.test")
                .unwrap();
            assert!(held("old"));
        }
        assert!(held("old"));
        {
            let transaction = bindings.transaction().unwrap();
            transaction.staged.publish(binding("new")).unwrap();
            assert!(held("old") && held("new"));
            assert_eq!(
                bindings
                    .certificate("account", "orders.example.test")
                    .unwrap()
                    .1,
                "old"
            );
        }
        assert!(held("old") && !held("new"));
        let transaction = bindings.transaction().unwrap();
        transaction.staged.publish(binding("new")).unwrap();
        transaction.commit().unwrap();
        assert!(!held("old") && held("new"));
        assert_eq!(
            bindings
                .certificate("account", "orders.example.test")
                .unwrap()
                .1,
            "new"
        );
        let transaction = bindings.transaction().unwrap();
        transaction
            .staged
            .remove("account", "us-east-1", "orders.example.test")
            .unwrap();
        assert!(held("new"));
        transaction.commit().unwrap();
        assert!(!held("new"));
        assert!(bindings
            .certificate("account", "orders.example.test")
            .is_none());
    }
}
