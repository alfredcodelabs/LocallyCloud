//! Resource and condition context for the native IAM operations, using the IAM SAR.
use super::*;

#[derive(Default)]
struct IamTarget {
    arn: String,
    tags: BTreeMap<String, String>,
    boundary: Option<String>,
    iam_resource_tag_alias: bool,
}

impl IamStsState {
    pub(super) fn default_iam_user(
        &self,
        request: &ServiceRequest,
        action: &str,
        query: &mut QueryRequest,
    ) {
        if query.get("UserName").is_some()
            || !matches!(
                action,
                "GetUser"
                    | "CreateAccessKey"
                    | "ListAccessKeys"
                    | "UpdateAccessKey"
                    | "DeleteAccessKey"
            )
        {
            return;
        }
        let Ok((identity, None)) =
            locallycloud_core::integration::authorization::verified_caller(self, request)
        else {
            return;
        };
        let Some(key) = identity.access_key_id.as_deref() else {
            return;
        };
        if self.sessions.resolve(key).is_some() {
            return;
        }
        if let Some(user) = self.store.user_for_key(&request.account_id, key) {
            query.set_user_name(user.user_name);
        }
    }

    #[cfg(test)]
    pub(super) fn iam_resource(
        &self,
        account: &str,
        action: &str,
        query: &QueryRequest,
    ) -> Result<String, IamStsError> {
        Ok(self.iam_target(account, action, query)?.arn)
    }

    fn iam_target(
        &self,
        account: &str,
        action: &str,
        query: &QueryRequest,
    ) -> Result<IamTarget, IamStsError> {
        let target = match action {
            "CreateUser" => IamTarget {
                arn: build_iam_arn(
                    account,
                    "user",
                    &crate::arn::normalize_path(query.get("Path").unwrap_or("/")),
                    query.require("UserName")?,
                ),
                ..Default::default()
            },
            "GetUser"
            | "DeleteUser"
            | "UpdateUser"
            | "TagUser"
            | "UntagUser"
            | "ListUserTags"
            | "ListGroupsForUser"
            | "AttachUserPolicy"
            | "DetachUserPolicy"
            | "ListAttachedUserPolicies"
            | "PutUserPolicy"
            | "GetUserPolicy"
            | "ListUserPolicies"
            | "DeleteUserPolicy"
            | "PutUserPermissionsBoundary"
            | "DeleteUserPermissionsBoundary"
            | "CreateAccessKey"
            | "ListAccessKeys"
            | "UpdateAccessKey"
            | "DeleteAccessKey" => {
                let name = query.require("UserName")?;
                match self.store.get_user(account, name) {
                    Some(entity) => IamTarget {
                        arn: entity.arn,
                        tags: entity.tags,
                        boundary: entity.permission_boundary,
                        iam_resource_tag_alias: true,
                    },
                    None => IamTarget {
                        arn: build_iam_arn(account, "user", "/", name),
                        ..Default::default()
                    },
                }
            }
            "CreateGroup" => IamTarget {
                arn: build_iam_arn(
                    account,
                    "group",
                    &crate::arn::normalize_path(query.get("Path").unwrap_or("/")),
                    query.require("GroupName")?,
                ),
                ..Default::default()
            },
            "GetGroup"
            | "AddUserToGroup"
            | "RemoveUserFromGroup"
            | "DeleteGroup"
            | "AttachGroupPolicy"
            | "DetachGroupPolicy"
            | "ListAttachedGroupPolicies"
            | "PutGroupPolicy"
            | "GetGroupPolicy"
            | "ListGroupPolicies"
            | "DeleteGroupPolicy" => {
                let name = query.require("GroupName")?;
                match self.store.get_group(account, name) {
                    Some(entity) => IamTarget {
                        arn: entity.arn,
                        ..Default::default()
                    },
                    None => IamTarget {
                        arn: build_iam_arn(account, "group", "/", name),
                        ..Default::default()
                    },
                }
            }
            "CreateRole" => IamTarget {
                arn: build_iam_arn(
                    account,
                    "role",
                    &crate::arn::normalize_path(query.get("Path").unwrap_or("/")),
                    query.require("RoleName")?,
                ),
                ..Default::default()
            },
            "GetRole"
            | "UpdateRole"
            | "UpdateAssumeRolePolicy"
            | "TagRole"
            | "UntagRole"
            | "ListRoleTags"
            | "DeleteRole"
            | "AttachRolePolicy"
            | "DetachRolePolicy"
            | "ListAttachedRolePolicies"
            | "PutRolePolicy"
            | "GetRolePolicy"
            | "ListRolePolicies"
            | "DeleteRolePolicy"
            | "PutRolePermissionsBoundary"
            | "DeleteRolePermissionsBoundary"
            | "ListInstanceProfilesForRole" => {
                let name = query.require("RoleName")?;
                match self.store.get_role(account, name) {
                    Some(entity) => IamTarget {
                        arn: entity.arn,
                        tags: entity.tags,
                        boundary: entity.permission_boundary,
                        iam_resource_tag_alias: true,
                    },
                    None => IamTarget {
                        arn: build_iam_arn(account, "role", "/", name),
                        ..Default::default()
                    },
                }
            }
            "CreatePolicy" => IamTarget {
                arn: build_iam_arn(
                    account,
                    "policy",
                    &crate::arn::normalize_path(query.get("Path").unwrap_or("/")),
                    query.require("PolicyName")?,
                ),
                ..Default::default()
            },
            "GetPolicy"
            | "DeletePolicy"
            | "TagPolicy"
            | "UntagPolicy"
            | "ListPolicyTags"
            | "CreatePolicyVersion"
            | "GetPolicyVersion"
            | "ListPolicyVersions"
            | "SetDefaultPolicyVersion"
            | "DeletePolicyVersion" => {
                let name = query.require("PolicyArn")?;
                match self
                    .store
                    .get_policy(account, name)
                    .or_else(|| self.store.get_policy("aws", name))
                {
                    Some(entity) => IamTarget {
                        arn: entity.arn,
                        tags: entity.tags,
                        ..Default::default()
                    },
                    None => IamTarget {
                        arn: name.to_owned(),
                        ..Default::default()
                    },
                }
            }
            "CreateInstanceProfile" => IamTarget {
                arn: build_iam_arn(
                    account,
                    "instance-profile",
                    &crate::arn::normalize_path(query.get("Path").unwrap_or("/")),
                    query.require("InstanceProfileName")?,
                ),
                ..Default::default()
            },
            "GetInstanceProfile"
            | "TagInstanceProfile"
            | "UntagInstanceProfile"
            | "ListInstanceProfileTags"
            | "AddRoleToInstanceProfile"
            | "RemoveRoleFromInstanceProfile"
            | "DeleteInstanceProfile" => {
                let name = query.require("InstanceProfileName")?;
                match self.store.get_instance_profile(account, name) {
                    Some(entity) => IamTarget {
                        arn: entity.arn,
                        tags: entity.tags,
                        ..Default::default()
                    },
                    None => IamTarget {
                        arn: build_iam_arn(account, "instance-profile", "/", name),
                        ..Default::default()
                    },
                }
            }
            "ListUsers"
            | "ListGroups"
            | "ListRoles"
            | "ListPolicies"
            | "ListInstanceProfiles"
            | "SimulateCustomPolicy" => IamTarget {
                arn: "*".into(),
                ..Default::default()
            },
            "SimulatePrincipalPolicy" => {
                let arn = query.require("PolicySourceArn")?;
                let prefix = format!("arn:aws:iam::{account}:");
                let resource = arn.strip_prefix(&prefix).ok_or_else(|| {
                    IamStsError::ValidationError(
                        "PolicySourceArn must identify an IAM principal in this account".into(),
                    )
                })?;
                let name = resource.rsplit('/').next().unwrap_or_default();
                let target = match resource.split_once('/') {
                    Some(("user", _)) => {
                        self.store.get_user(account, name).map(|entity| IamTarget {
                            arn: entity.arn,
                            tags: entity.tags,
                            boundary: entity.permission_boundary,
                            iam_resource_tag_alias: true,
                        })
                    }
                    Some(("role", _)) => {
                        self.store.get_role(account, name).map(|entity| IamTarget {
                            arn: entity.arn,
                            tags: entity.tags,
                            boundary: entity.permission_boundary,
                            iam_resource_tag_alias: true,
                        })
                    }
                    Some(("group", _)) => {
                        self.store.get_group(account, name).map(|entity| IamTarget {
                            arn: entity.arn,
                            ..Default::default()
                        })
                    }
                    _ => None,
                }
                .ok_or_else(|| IamStsError::NoSuchEntity("IAM policy source not found".into()))?;
                if target.arn != arn {
                    return Err(IamStsError::NoSuchEntity(
                        "IAM policy source not found".into(),
                    ));
                }
                target
            }
            other => {
                return Err(IamStsError::InvalidAction(format!(
                    "unsupported IAM action {other}"
                )))
            }
        };
        Ok(target)
    }

    pub(super) fn authorize_iam(
        &self,
        request: &ServiceRequest,
        action: &str,
        query: &QueryRequest,
    ) -> Result<(), IamStsError> {
        let target = self.iam_target(&request.account_id, action, query)?;
        let mut context =
            locallycloud_core::integration::request_context::verified_request_context(request);
        for (key, value) in &target.tags {
            context
                .entry(format!("aws:resourcetag/{}", key.to_ascii_lowercase()))
                .or_default()
                .push(value.clone());
            if target.iam_resource_tag_alias {
                context
                    .entry(format!("iam:resourcetag/{}", key.to_ascii_lowercase()))
                    .or_default()
                    .push(value.clone());
            }
        }
        if matches!(
            action,
            "CreateUser"
                | "TagUser"
                | "CreateRole"
                | "TagRole"
                | "CreatePolicy"
                | "TagPolicy"
                | "CreateInstanceProfile"
                | "TagInstanceProfile"
        ) {
            for (key, value) in query.tags("Tags.member") {
                context
                    .entry(format!("aws:requesttag/{}", key.to_ascii_lowercase()))
                    .or_default()
                    .push(value);
            }
        }
        if matches!(
            action,
            "CreateUser"
                | "TagUser"
                | "UntagUser"
                | "CreateRole"
                | "TagRole"
                | "UntagRole"
                | "CreatePolicy"
                | "TagPolicy"
                | "UntagPolicy"
                | "CreateInstanceProfile"
                | "TagInstanceProfile"
                | "UntagInstanceProfile"
        ) {
            let keys = if action.starts_with("Untag") {
                query.list("TagKeys.member")
            } else {
                query
                    .tags("Tags.member")
                    .into_iter()
                    .map(|(key, _)| key)
                    .collect()
            };
            if !keys.is_empty() {
                context.insert("aws:tagkeys".into(), keys);
            }
        }
        if matches!(
            action,
            "AttachUserPolicy"
                | "AttachGroupPolicy"
                | "AttachRolePolicy"
                | "DetachUserPolicy"
                | "DetachGroupPolicy"
                | "DetachRolePolicy"
        ) {
            if let Some(arn) = query.get("PolicyArn") {
                context.insert("iam:policyarn".into(), vec![arn.into()]);
            }
        }
        if matches!(
            action,
            "CreateUser"
                | "CreateRole"
                | "GetRole"
                | "UpdateRole"
                | "UpdateAssumeRolePolicy"
                | "DeleteRole"
                | "AttachUserPolicy"
                | "AttachRolePolicy"
                | "DetachUserPolicy"
                | "DetachRolePolicy"
                | "PutUserPolicy"
                | "PutRolePolicy"
                | "DeleteUserPolicy"
                | "DeleteRolePolicy"
                | "PutUserPermissionsBoundary"
                | "PutRolePermissionsBoundary"
                | "DeleteUserPermissionsBoundary"
                | "DeleteRolePermissionsBoundary"
        ) {
            let boundary = match action {
                "CreateUser"
                | "CreateRole"
                | "PutUserPermissionsBoundary"
                | "PutRolePermissionsBoundary" => query.get("PermissionsBoundary"),
                _ => target.boundary.as_deref(),
            };
            if let Some(arn) = boundary {
                context.insert("iam:permissionsboundary".into(), vec![arn.into()]);
            }
        }
        self.enforce_with_context(request, "iam", action, &target.arn, context.clone())?;
        let tag_action = match action {
            "CreateUser" => Some("TagUser"),
            "CreateRole" => Some("TagRole"),
            "CreatePolicy" => Some("TagPolicy"),
            "CreateInstanceProfile" => Some("TagInstanceProfile"),
            _ => None,
        };
        if let Some(tag_action) = tag_action.filter(|_| !query.tags("Tags.member").is_empty()) {
            context.remove("iam:permissionsboundary");
            self.enforce_with_context(request, "iam", tag_action, &target.arn, context)?;
        }
        if action == "AddRoleToInstanceProfile" {
            let role = self
                .store
                .get_role(&request.account_id, query.require("RoleName")?)
                .ok_or_else(|| IamStsError::NoSuchEntity("role not found".into()))?;
            let mut context =
                locallycloud_core::integration::request_context::verified_request_context(request);
            context.insert(
                "iam:passedtoservice".into(),
                vec!["ec2.amazonaws.com".into()],
            );
            context.insert(
                "iam:associatedresourcearn".into(),
                vec![format!("arn:aws:ec2:*:{}:instance/*", request.account_id)],
            );
            for (key, value) in role.tags {
                context
                    .entry(format!("aws:resourcetag/{}", key.to_ascii_lowercase()))
                    .or_default()
                    .push(value.clone());
                context
                    .entry(format!("iam:resourcetag/{}", key.to_ascii_lowercase()))
                    .or_default()
                    .push(value);
            }
            self.enforce_with_context(request, "iam", "PassRole", &role.arn, context)?;
        }
        Ok(())
    }
}
