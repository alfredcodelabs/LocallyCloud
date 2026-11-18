//! The exact resource keys read or written by each IAM control-plane mutation.
use crate::arn::{build_iam_arn, normalize_path};
use crate::query::QueryRequest;
use std::collections::BTreeSet;

type Keys = BTreeSet<(String, String)>;

#[derive(Default)]
pub(crate) struct ResourceScope {
    pub users: Keys,
    pub groups: Keys,
    pub roles: Keys,
    pub policies: Keys,
    pub instance_profiles: Keys,
}

impl ResourceScope {
    pub fn for_operation(account: &str, action: &str, q: &QueryRequest) -> Self {
        let mut scope = Self::default();
        let add = |keys: &mut Keys, parameter: &str| {
            if let Some(name) = q.get(parameter) {
                keys.insert((account.into(), name.into()));
            }
        };
        let policy = |keys: &mut Keys, parameter: &str| {
            if let Some(arn) = q.get(parameter) {
                keys.insert((account.into(), arn.into()));
                keys.insert(("aws".into(), arn.into()));
            }
        };
        match action {
            "CreateUser"
            | "DeleteUser"
            | "UpdateUser"
            | "TagUser"
            | "UntagUser"
            | "CreateAccessKey"
            | "UpdateAccessKey"
            | "DeleteAccessKey"
            | "PutUserPolicy"
            | "DeleteUserPolicy"
            | "PutUserPermissionsBoundary"
            | "DeleteUserPermissionsBoundary" => {
                add(&mut scope.users, "UserName");
                if action == "UpdateUser" {
                    add(&mut scope.users, "NewUserName");
                }
                if matches!(action, "CreateUser" | "PutUserPermissionsBoundary") {
                    policy(&mut scope.policies, "PermissionsBoundary");
                }
            }
            "CreateGroup" | "DeleteGroup" | "PutGroupPolicy" | "DeleteGroupPolicy" => {
                add(&mut scope.groups, "GroupName");
            }
            "AddUserToGroup" | "RemoveUserFromGroup" => {
                add(&mut scope.users, "UserName");
                add(&mut scope.groups, "GroupName");
            }
            "CreateRole"
            | "DeleteRole"
            | "UpdateRole"
            | "UpdateAssumeRolePolicy"
            | "TagRole"
            | "UntagRole"
            | "PutRolePolicy"
            | "DeleteRolePolicy"
            | "PutRolePermissionsBoundary"
            | "DeleteRolePermissionsBoundary" => {
                add(&mut scope.roles, "RoleName");
                if matches!(action, "CreateRole" | "PutRolePermissionsBoundary") {
                    policy(&mut scope.policies, "PermissionsBoundary");
                }
            }
            "AttachUserPolicy" | "DetachUserPolicy" => {
                add(&mut scope.users, "UserName");
                policy(&mut scope.policies, "PolicyArn");
            }
            "AttachGroupPolicy" | "DetachGroupPolicy" => {
                add(&mut scope.groups, "GroupName");
                policy(&mut scope.policies, "PolicyArn");
            }
            "AttachRolePolicy" | "DetachRolePolicy" => {
                add(&mut scope.roles, "RoleName");
                policy(&mut scope.policies, "PolicyArn");
            }
            "CreatePolicy" => {
                if let Some(name) = q.get("PolicyName") {
                    let path = normalize_path(q.get("Path").unwrap_or("/"));
                    scope.policies.insert((
                        account.into(),
                        build_iam_arn(account, "policy", &path, name),
                    ));
                }
            }
            "DeletePolicy"
            | "TagPolicy"
            | "UntagPolicy"
            | "CreatePolicyVersion"
            | "SetDefaultPolicyVersion"
            | "DeletePolicyVersion" => {
                policy(&mut scope.policies, "PolicyArn");
            }
            "CreateInstanceProfile"
            | "DeleteInstanceProfile"
            | "TagInstanceProfile"
            | "UntagInstanceProfile"
            | "RemoveRoleFromInstanceProfile" => {
                add(&mut scope.instance_profiles, "InstanceProfileName");
            }
            "AddRoleToInstanceProfile" => {
                add(&mut scope.instance_profiles, "InstanceProfileName");
                add(&mut scope.roles, "RoleName");
            }
            // Unsupported actions still reach the normal AWS error without copying inventory.
            _ => {}
        }
        scope
    }
}
