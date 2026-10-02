use super::*;

pub(super) fn default_egress() -> Vec<IngressRule> {
    vec![IngressRule {
        protocol: "-1".into(),
        from_port: None,
        to_port: None,
        cidr: Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid IPv4 default route"),
    }]
}

impl Ec2Handler {
    pub(super) fn authorize_security_group_egress(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        input.allow_ingress()?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let (protocol, from_port, to_port, cidr) = input.ingress_rule()?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let group = scope.security_groups.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidGroup.NotFound",
                format!("The security group '{id}' does not exist"),
            )
        })?;
        if group.egress.iter().any(|rule| {
            rule.protocol == protocol
                && rule.from_port == from_port
                && rule.to_port == to_port
                && rule.cidr == cidr
        }) {
            return Err(Ec2Error::new(
                "InvalidPermission.Duplicate",
                "The specified rule already exists",
            ));
        }
        group.egress.push(IngressRule {
            protocol: protocol.clone(),
            from_port,
            to_port,
            cidr,
        });
        let rule_id = resource_id("sgr");
        Ok(format!("<return>true</return><securityGroupRuleSet><item><groupId>{}</groupId><securityGroupRuleId>{}</securityGroupRuleId><isEgress>true</isEgress><ipProtocol>{}</ipProtocol>{}<cidrIpv4>{}</cidrIpv4></item></securityGroupRuleSet>", escape(id), escape(&rule_id), escape(&protocol), ports_xml(from_port, to_port), cidr))
    }

    pub(super) fn revoke_security_group_egress(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        // Terraform attempts to revoke AWS's default IPv6 rule too. VPCs in this
        // emulator have no IPv6 range, so that rule is genuinely absent.
        if input
            .fields
            .contains_key("IpPermissions.1.Ipv6Ranges.1.CidrIpv6")
        {
            input.allow(&[
                "Action",
                "Version",
                "DryRun",
                "GroupId",
                "IpPermissions.1.IpProtocol",
                "IpPermissions.1.FromPort",
                "IpPermissions.1.ToPort",
                "IpPermissions.1.Ipv6Ranges.1.CidrIpv6",
            ])?;
            input.dry_run()?;
            let id = input.required("GroupId")?;
            if input.required("IpPermissions.1.IpProtocol")? != "-1"
                || input.required("IpPermissions.1.FromPort")? != "0"
                || input.required("IpPermissions.1.ToPort")? != "0"
                || input.required("IpPermissions.1.Ipv6Ranges.1.CidrIpv6")? != "::/0"
            {
                return Err(Ec2Error::unsupported("IPv6 egress rule"));
            }
            let state = self.scopes.lock().unwrap();
            if !state
                .get(&key)
                .is_some_and(|scope| scope.security_groups.contains_key(id))
            {
                return Err(Ec2Error::new(
                    "InvalidGroup.NotFound",
                    format!("The security group '{id}' does not exist"),
                ));
            }
            return Err(Ec2Error::new(
                "InvalidPermission.NotFound",
                "The specified IPv6 rule does not exist",
            ));
        }
        input.allow_ingress()?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let (protocol, from_port, to_port, cidr) = input.ingress_rule()?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key).or_default();
        let group = scope.security_groups.get_mut(id).ok_or_else(|| {
            Ec2Error::new(
                "InvalidGroup.NotFound",
                format!("The security group '{id}' does not exist"),
            )
        })?;
        let before = group.egress.len();
        group.egress.retain(|rule| {
            !(rule.protocol == protocol
                && rule.from_port == from_port
                && rule.to_port == to_port
                && rule.cidr == cidr)
        });
        if group.egress.len() == before {
            return Err(Ec2Error::new(
                "InvalidPermission.NotFound",
                "The specified rule does not exist",
            ));
        }
        Ok("<return>true</return>".into())
    }
}
