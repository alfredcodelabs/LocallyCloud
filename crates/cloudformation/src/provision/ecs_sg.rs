//! Standalone SG-reference rules avoid CloudFormation dependency cycles.
use super::*;
pub(super) fn validate_sg_rule_names(id: &str, kind: &str, props: &Value) -> Result<(), CfnError> {
    let peer = match kind {
        "AWS::EC2::SecurityGroupIngress" => "SourceSecurityGroupId",
        "AWS::EC2::SecurityGroupEgress" => "DestinationSecurityGroupId",
        _ => return Ok(()),
    };
    ensure_known_properties(
        id,
        kind,
        props,
        &[
            "GroupId",
            "IpProtocol",
            "FromPort",
            "ToPort",
            "CidrIp",
            peer,
        ],
    )
}
fn rule_fields(id: &str, kind: &str, props: &Value) -> Result<Vec<(String, String)>, CfnError> {
    validate_sg_rule_names(id, kind, props)?;
    let group = required_property(props, "GroupId", id)?;
    let protocol = required_property(props, "IpProtocol", id)?;
    let peer = if kind == "AWS::EC2::SecurityGroupIngress" {
        "SourceSecurityGroupId"
    } else {
        "DestinationSecurityGroupId"
    };
    let (key, value) = match (props.get("CidrIp"), props.get(peer)) {
        (Some(_), None) => (
            "IpPermissions.1.IpRanges.1.CidrIp",
            required_property(props, "CidrIp", id)?,
        ),
        (None, Some(_)) => (
            "IpPermissions.1.Groups.1.GroupId",
            required_property(props, peer, id)?,
        ),
        _ => {
            return Err(CfnError::Validation(format!(
                "{id} requires exactly one CIDR or SG peer"
            )))
        }
    };
    let mut fields = vec![
        ("GroupId".into(), group),
        ("IpPermissions.1.IpProtocol".into(), protocol.clone()),
        (key.into(), value),
    ];
    if !["tcp", "udp", "-1"].contains(&protocol.as_str()) {
        return Err(CfnError::Validation(format!(
            "{id} requires tcp, udp or -1 protocol"
        )));
    }
    if protocol != "-1" {
        let from = props["FromPort"]
            .as_u64()
            .filter(|value| *value <= u16::MAX as u64)
            .ok_or_else(|| CfnError::Validation(format!("{id} requires numeric FromPort")))?;
        let to = props["ToPort"]
            .as_u64()
            .filter(|value| *value <= u16::MAX as u64 && *value >= from)
            .ok_or_else(|| CfnError::Validation(format!("{id} requires ordered numeric ToPort")))?;
        fields.push(("IpPermissions.1.FromPort".into(), from.to_string()));
        fields.push(("IpPermissions.1.ToPort".into(), to.to_string()));
    } else if ["FromPort", "ToPort"].iter().any(|key| {
        props
            .get(*key)
            .is_some_and(|value| value.as_u64() != Some(0))
    }) {
        return Err(CfnError::Validation(format!(
            "{id} protocol -1 ports must be absent or zero"
        )));
    }
    Ok(fields)
}
impl Provisioner {
    pub(super) async fn ecs_sg_rule(
        &self,
        id: &str,
        kind: &str,
        props: &Value,
        remove: bool,
    ) -> Result<ResolvedResource, CfnError> {
        let fields = rule_fields(id, kind, props)?;
        let suffix = if kind == "AWS::EC2::SecurityGroupIngress" {
            "SecurityGroupIngress"
        } else {
            "SecurityGroupEgress"
        };
        let action = format!("{}{suffix}", if remove { "Revoke" } else { "Authorize" });
        let fields: Vec<_> = fields
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        let xml = match self.call_ec2(&action, &fields, id).await {
            Ok(xml) => xml,
            Err(error)
                if remove
                    && [
                        "<Code>InvalidPermission.NotFound</Code>",
                        "<Code>InvalidGroup.NotFound</Code>",
                    ]
                    .iter()
                    .any(|code| error.to_string().contains(code)) =>
            {
                return Ok(ResolvedResource {
                    ref_value: String::new(),
                    attributes: Default::default(),
                })
            }
            Err(error) => return Err(error),
        };
        let ref_value = if remove {
            String::new()
        } else {
            ec2::ec2_rule_id(&xml, id)?
        };
        Ok(ResolvedResource {
            ref_value,
            attributes: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    #[tokio::test]
    async fn native_sg_reference_rules_create_and_remove_actual_owned_rules() {
        let registry = ServiceRegistry::with_known_services();
        locallycloud_ec2::register(&registry);
        let provisioner = Provisioner::new(
            Arc::downgrade(&registry),
            "us-east-1".into(),
            "111111111111".into(),
        );
        let vpc = provisioner
            .ec2_vpc("Vpc", &json!({"CidrBlock":"10.71.0.0/16"}))
            .await
            .unwrap();
        let a = provisioner
            .ec2_security_group(
                "A",
                "stack",
                &json!({"VpcId":vpc.ref_value,"GroupDescription":"ALB"}),
            )
            .await
            .unwrap();
        let b = provisioner.ec2_security_group("B","stack",&json!({"VpcId":vpc.ref_value,"GroupDescription":"task","SecurityGroupIngress":[{"IpProtocol":"tcp","FromPort":8081,"ToPort":8081,"SourceSecurityGroupId":a.ref_value}]})).await.unwrap();
        let props = json!({"GroupId":b.ref_value,"IpProtocol":"tcp","FromPort":8080,"ToPort":8080,"SourceSecurityGroupId":a.ref_value});
        let rule = provisioner
            .ecs_sg_rule("Ingress", "AWS::EC2::SecurityGroupIngress", &props, false)
            .await
            .unwrap();
        assert!(rule.ref_value.starts_with("sgr-"));
        assert!(provisioner
            .ecs_sg_rule("Duplicate", "AWS::EC2::SecurityGroupIngress", &props, false)
            .await
            .is_err());
        provisioner
            .ecs_sg_rule(
                &rule.ref_value,
                "AWS::EC2::SecurityGroupIngress",
                &props,
                true,
            )
            .await
            .unwrap();
        // Remove the inline reference before deleting the referenced SG.
        provisioner
            .delete_ec2("DeleteSecurityGroup", "GroupId", &b.ref_value)
            .await
            .unwrap();
        provisioner
            .delete_ec2("DeleteSecurityGroup", "GroupId", &a.ref_value)
            .await
            .unwrap();
        provisioner
            .delete_ec2("DeleteVpc", "VpcId", &vpc.ref_value)
            .await
            .unwrap();
    }
}
