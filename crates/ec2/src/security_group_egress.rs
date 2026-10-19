use super::*;

pub(super) fn default_egress() -> Vec<IngressRule> {
    vec![IngressRule {
        protocol: "-1".into(),
        from_port: None,
        to_port: None,
        peer: RulePeer::Cidr(
            Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).expect("valid IPv4 default route"),
        ),
    }]
}

impl Ec2Handler {
    pub(super) fn authorize_security_group_egress(
        &self,
        key: (String, String),
        input: &Input,
    ) -> Result<String, Ec2Error> {
        self.change_security_rule(key, input, true, true)
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
        self.change_security_rule(key, input, true, false)
    }
}

impl Ec2Handler {
    pub(super) fn change_security_rule(
        &self,
        key: (String, String),
        input: &Input,
        egress: bool,
        authorize: bool,
    ) -> Result<String, Ec2Error> {
        input.allow_ingress()?;
        input.dry_run()?;
        let id = input.required("GroupId")?;
        let (protocol, from_port, to_port, peer) = input.ingress_rule()?;
        let mut state = self.scopes.lock().unwrap();
        let scope = state.entry(key.clone()).or_default();
        let group = scope.security_groups.get(id).ok_or_else(|| {
            Ec2Error::new("InvalidGroup.NotFound", "The security group does not exist")
        })?;
        if let RulePeer::Group(peer_id) = &peer {
            let referenced = scope.security_groups.get(peer_id).ok_or_else(|| {
                Ec2Error::new(
                    "InvalidGroup.NotFound",
                    "The referenced security group does not exist",
                )
            })?;
            if referenced.vpc_id != group.vpc_id {
                return Err(Ec2Error::new(
                    "InvalidGroup.NotFound",
                    "The referenced security group is not in this VPC",
                ));
            }
            if input
                .one("IpPermissions.1.Groups.1.UserId")?
                .is_some_and(|owner| owner != key.0)
            {
                return Err(Ec2Error::new(
                    "InvalidGroup.NotFound",
                    "The referenced security group is not in this account",
                ));
            }
        }
        let mut group = scope.security_groups.get(id).cloned().ok_or_else(|| {
            Ec2Error::new("InvalidGroup.NotFound", "The security group does not exist")
        })?;
        let rules = if egress {
            &mut group.egress
        } else {
            &mut group.ingress
        };
        let position = rules.iter().position(|rule| {
            rule.protocol == protocol
                && rule.from_port == from_port
                && rule.to_port == to_port
                && rule.peer == peer
        });
        match (authorize, position) {
            (true, Some(_)) => {
                return Err(Ec2Error::new(
                    "InvalidPermission.Duplicate",
                    "The specified rule already exists",
                ))
            }
            (false, None) => {
                return Err(Ec2Error::new(
                    "InvalidPermission.NotFound",
                    "The specified rule does not exist",
                ))
            }
            (false, Some(index)) => {
                rules.remove(index);
                self.persist(&key, &[Change::put("sg", id, &group)?])?;
                scope.security_groups.insert(id.into(), group);
                return Ok("<return>true</return>".into());
            }
            (true, None) => {}
        }
        let peer_xml = match &peer {
            RulePeer::Cidr(cidr) => format!("<cidrIpv4>{cidr}</cidrIpv4>"),
            RulePeer::Group(peer_id) => format!("<referencedGroupInfo><groupId>{}</groupId><userId>{}</userId></referencedGroupInfo>", escape(peer_id), escape(&key.0)),
        };
        let response = format!("<return>true</return><securityGroupRuleSet><item><groupId>{}</groupId><securityGroupRuleId>{}</securityGroupRuleId><isEgress>{egress}</isEgress><ipProtocol>{}</ipProtocol>{}{peer_xml}</item></securityGroupRuleSet>", escape(id), resource_id("sgr"), escape(&protocol), ports_xml(from_port,to_port));
        rules.push(IngressRule {
            protocol,
            from_port,
            to_port,
            peer,
        });
        self.persist(&key, &[Change::put("sg", id, &group)?])?;
        scope.security_groups.insert(id.into(), group);
        Ok(response)
    }
}

pub(super) fn permission_xml(rule: &IngressRule, owner: &str) -> String {
    let peer = match &rule.peer {
        RulePeer::Cidr(cidr) => {
            format!("<groups/><ipRanges><item><cidrIp>{cidr}</cidrIp></item></ipRanges>")
        }
        RulePeer::Group(id) => format!(
            "<groups><item><userId>{}</userId><groupId>{}</groupId></item></groups><ipRanges/>",
            escape(owner),
            escape(id)
        ),
    };
    format!(
        "<item><ipProtocol>{}</ipProtocol>{}{peer}<ipv6Ranges/><prefixListIds/></item>",
        escape(&rule.protocol),
        ports_xml(rule.from_port, rule.to_port)
    )
}
