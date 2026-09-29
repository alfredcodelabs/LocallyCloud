//! IAM control-plane operations.
//!
//! Each operation returns the inner `<{Action}Result>` XML body (empty for metadata-only
//! responses); the service layer wraps it in the Query response envelope and returns HTTP
//! 200. Errors carry the AWS code/status via [`IamStsError`].

use std::collections::BTreeMap;

use crate::arn::{build_iam_arn, matches_prefix, normalize_path};
use crate::error::IamStsError;
use crate::ids;
use crate::model::{
    now_iso8601, tags_xml, urlencode_doc, AccessKey, IamGroup, IamPolicy, IamRole, IamUser,
    InstanceProfile, PolicyVersion,
};
use crate::policy::{evaluate, Decision, EvalRequest, PolicyDocument};
use crate::query::{text_el, xml_escape, QueryRequest};
use crate::store::{Created, IamStore};

/// The inner XML result body of a successful operation.
pub type OpResult = Result<String, IamStsError>;

/// Maximum versions per managed policy (AWS limit).
const MAX_POLICY_VERSIONS: usize = 5;
/// Maximum access keys per user (AWS limit).
const MAX_ACCESS_KEYS: usize = 2;
/// Default role max session duration (seconds).
const DEFAULT_MAX_SESSION_DURATION: u32 = 3600;

fn no_such_entity(what: &str) -> IamStsError {
    IamStsError::NoSuchEntity(format!("{what} cannot be found"))
}

fn tags_map(pairs: Vec<(String, String)>) -> BTreeMap<String, String> {
    pairs.into_iter().collect()
}

/// `<member>...<member>` wrapper for a list of pre-serialized members.
fn members(items: impl IntoIterator<Item = String>) -> String {
    items.into_iter().collect()
}

// ============================ Users ============================================

pub fn create_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let path = normalize_path(q.get("Path").unwrap_or("/"));
    let user = IamUser {
        user_name: name.to_string(),
        user_id: ids::unique_id(ids::USER),
        arn: build_iam_arn(account, "user", &path, name),
        path,
        create_date: now_iso8601(),
        tags: tags_map(q.tags("Tags.member")),
        attached_policies: Vec::new(),
        inline_policies: BTreeMap::new(),
        groups: Vec::new(),
        permission_boundary: None,
        access_keys: Vec::new(),
    };
    match store.create_user(account, user) {
        Created::Inserted(u) => Ok(u.xml()),
        Created::AlreadyExists => Err(IamStsError::EntityAlreadyExists(format!(
            "user {name} already exists"
        ))),
    }
}

pub fn get_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    // GetUser with no UserName returns the caller; localcloud has no caller user, so it
    // requires an explicit UserName.
    let name = q.require("UserName")?;
    let user = store
        .get_user(account, name)
        .ok_or_else(|| no_such_entity("user"))?;
    Ok(user.xml())
}

pub fn delete_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let user = store
        .get_user(account, name)
        .ok_or_else(|| no_such_entity("user"))?;
    if !user.attached_policies.is_empty()
        || !user.groups.is_empty()
        || !user.inline_policies.is_empty()
    {
        return Err(IamStsError::DeleteConflict(format!(
            "user {name} has attached resources and cannot be deleted"
        )));
    }
    store.remove_user(account, name);
    Ok(String::new())
}

pub fn update_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let new_name = q.get("NewUserName");
    let new_path = q.get("NewPath").map(normalize_path);
    if store.get_user(account, name).is_none() {
        return Err(no_such_entity("user"));
    }
    if let Some(new_name) = new_name {
        if new_name != name && store.get_user(account, new_name).is_some() {
            return Err(IamStsError::EntityAlreadyExists(format!(
                "user {new_name} already exists"
            )));
        }
        if new_name != name {
            let mut user = store
                .remove_user(account, name)
                .ok_or_else(|| no_such_entity("user"))?;
            user.user_name = new_name.to_string();
            if let Some(p) = &new_path {
                user.path = p.clone();
            }
            user.arn = build_iam_arn(account, "user", &user.path, new_name);
            store.create_user(account, user);
            return Ok(String::new());
        }
    }
    if let Some(p) = new_path {
        store.update_user(account, name, |u| {
            u.path = p.clone();
            u.arn = build_iam_arn(account, "user", &p, &u.user_name);
        });
    }
    Ok(String::new())
}

pub fn list_users(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let prefix = q.get("PathPrefix");
    let mut users: Vec<IamUser> = store
        .list_users(account)
        .into_iter()
        .filter(|u| matches_prefix(&u.path, prefix))
        .collect();
    users.sort_by(|a, b| a.user_name.cmp(&b.user_name));
    let body = members(users.iter().map(|u| u.member_xml()));
    Ok(format!(
        "<Users>{body}</Users><IsTruncated>false</IsTruncated>"
    ))
}

pub fn tag_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let tags = tags_map(q.tags("Tags.member"));
    if !store.update_user(account, name, |u| u.tags.extend(tags.clone())) {
        return Err(no_such_entity("user"));
    }
    Ok(String::new())
}

pub fn untag_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let keys = q.list("TagKeys.member");
    if !store.update_user(account, name, |u| u.tags.retain(|k, _| !keys.contains(k))) {
        return Err(no_such_entity("user"));
    }
    Ok(String::new())
}

pub fn list_user_tags(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("UserName")?;
    let user = store
        .get_user(account, name)
        .ok_or_else(|| no_such_entity("user"))?;
    Ok(format!(
        "{}<IsTruncated>false</IsTruncated>",
        tags_xml(&user.tags)
    ))
}

// ============================ Groups ===========================================

pub fn create_group(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("GroupName")?;
    let path = normalize_path(q.get("Path").unwrap_or("/"));
    let group = IamGroup {
        group_name: name.to_string(),
        group_id: ids::unique_id(ids::GROUP),
        arn: build_iam_arn(account, "group", &path, name),
        path,
        create_date: now_iso8601(),
        members: Vec::new(),
        attached_policies: Vec::new(),
        inline_policies: BTreeMap::new(),
    };
    match store.create_group(account, group) {
        Created::Inserted(g) => Ok(g.xml()),
        Created::AlreadyExists => Err(IamStsError::EntityAlreadyExists(format!(
            "group {name} already exists"
        ))),
    }
}

pub fn get_group(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("GroupName")?;
    let group = store
        .get_group(account, name)
        .ok_or_else(|| no_such_entity("group"))?;
    let member_users: Vec<IamUser> = group
        .members
        .iter()
        .filter_map(|m| store.get_user(account, m))
        .collect();
    let users_xml = members(member_users.iter().map(|u| u.member_xml()));
    Ok(format!(
        "{}<Users>{users_xml}</Users><IsTruncated>false</IsTruncated>",
        group.xml()
    ))
}

pub fn list_groups(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let prefix = q.get("PathPrefix");
    let mut groups: Vec<IamGroup> = store
        .list_groups(account)
        .into_iter()
        .filter(|g| matches_prefix(&g.path, prefix))
        .collect();
    groups.sort_by(|a, b| a.group_name.cmp(&b.group_name));
    let body = members(groups.iter().map(|g| g.member_xml()));
    Ok(format!(
        "<Groups>{body}</Groups><IsTruncated>false</IsTruncated>"
    ))
}

pub fn add_user_to_group(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let group_name = q.require("GroupName")?;
    let user_name = q.require("UserName")?;
    if store.get_group(account, group_name).is_none() {
        return Err(no_such_entity("group"));
    }
    if store.get_user(account, user_name).is_none() {
        return Err(no_such_entity("user"));
    }
    store.update_group(account, group_name, |g| {
        if !g.members.contains(&user_name.to_string()) {
            g.members.push(user_name.to_string());
        }
    });
    store.update_user(account, user_name, |u| {
        if !u.groups.contains(&group_name.to_string()) {
            u.groups.push(group_name.to_string());
        }
    });
    Ok(String::new())
}

pub fn remove_user_from_group(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let group_name = q.require("GroupName")?;
    let user_name = q.require("UserName")?;
    if store.get_group(account, group_name).is_none() {
        return Err(no_such_entity("group"));
    }
    if store.get_user(account, user_name).is_none() {
        return Err(no_such_entity("user"));
    }
    store.update_group(account, group_name, |g| {
        g.members.retain(|m| m != user_name)
    });
    store.update_user(account, user_name, |u| {
        u.groups.retain(|gname| gname != group_name)
    });
    Ok(String::new())
}

pub fn list_groups_for_user(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let user_name = q.require("UserName")?;
    let user = store
        .get_user(account, user_name)
        .ok_or_else(|| no_such_entity("user"))?;
    let groups: Vec<IamGroup> = user
        .groups
        .iter()
        .filter_map(|g| store.get_group(account, g))
        .collect();
    let body = members(groups.iter().map(|g| g.member_xml()));
    Ok(format!(
        "<Groups>{body}</Groups><IsTruncated>false</IsTruncated>"
    ))
}

pub fn delete_group(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("GroupName")?;
    let group = store
        .get_group(account, name)
        .ok_or_else(|| no_such_entity("group"))?;
    if !group.attached_policies.is_empty()
        || !group.inline_policies.is_empty()
        || !group.members.is_empty()
    {
        return Err(IamStsError::DeleteConflict(format!(
            "group {name} has attached resources and cannot be deleted"
        )));
    }
    store.remove_group(account, name);
    Ok(String::new())
}

// ============================ Roles ============================================

pub fn create_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let trust = q.require("AssumeRolePolicyDocument")?;
    PolicyDocument::parse_trust(trust)?;
    let path = normalize_path(q.get("Path").unwrap_or("/"));
    let max_session = q
        .get("MaxSessionDuration")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_MAX_SESSION_DURATION);
    let role = IamRole {
        role_name: name.to_string(),
        role_id: ids::unique_id(ids::ROLE),
        arn: build_iam_arn(account, "role", &path, name),
        path,
        create_date: now_iso8601(),
        assume_role_policy_document: trust.to_string(),
        description: q.get("Description").map(str::to_string),
        max_session_duration: max_session,
        tags: tags_map(q.tags("Tags.member")),
        attached_policies: Vec::new(),
        inline_policies: BTreeMap::new(),
        permission_boundary: None,
    };
    match store.create_role(account, role) {
        Created::Inserted(r) => Ok(r.xml()),
        Created::AlreadyExists => Err(IamStsError::EntityAlreadyExists(format!(
            "role {name} already exists"
        ))),
    }
}

pub fn get_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let role = store
        .get_role(account, name)
        .ok_or_else(|| no_such_entity("role"))?;
    Ok(role.xml())
}

pub fn list_roles(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let prefix = q.get("PathPrefix");
    let mut roles: Vec<IamRole> = store
        .list_roles(account)
        .into_iter()
        .filter(|r| matches_prefix(&r.path, prefix))
        .collect();
    roles.sort_by(|a, b| a.role_name.cmp(&b.role_name));
    let body = members(roles.iter().map(|r| r.member_xml()));
    Ok(format!(
        "<Roles>{body}</Roles><IsTruncated>false</IsTruncated>"
    ))
}

pub fn update_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let description = q.get("Description").map(str::to_string);
    let max_session = q
        .get("MaxSessionDuration")
        .and_then(|v| v.parse::<u32>().ok());
    if !store.update_role(account, name, |r| {
        if let Some(d) = description {
            r.description = Some(d);
        }
        if let Some(m) = max_session {
            r.max_session_duration = m;
        }
    }) {
        return Err(no_such_entity("role"));
    }
    Ok(String::new())
}

pub fn update_assume_role_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let trust = q.require("PolicyDocument")?.to_string();
    if store.get_role(account, name).is_none() {
        return Err(no_such_entity("role"));
    }
    PolicyDocument::parse_trust(&trust)?;
    if !store.update_role(account, name, |role| {
        role.assume_role_policy_document = trust
    }) {
        return Err(no_such_entity("role"));
    }
    Ok(String::new())
}

pub fn tag_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let tags = tags_map(q.tags("Tags.member"));
    if !store.update_role(account, name, |r| r.tags.extend(tags.clone())) {
        return Err(no_such_entity("role"));
    }
    Ok(String::new())
}

pub fn untag_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let keys = q.list("TagKeys.member");
    if !store.update_role(account, name, |r| r.tags.retain(|k, _| !keys.contains(k))) {
        return Err(no_such_entity("role"));
    }
    Ok(String::new())
}

pub fn list_role_tags(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let role = store
        .get_role(account, name)
        .ok_or_else(|| no_such_entity("role"))?;
    Ok(format!(
        "{}<IsTruncated>false</IsTruncated>",
        tags_xml(&role.tags)
    ))
}

pub fn delete_role(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("RoleName")?;
    let role = store
        .get_role(account, name)
        .ok_or_else(|| no_such_entity("role"))?;
    if !role.attached_policies.is_empty() || !role.inline_policies.is_empty() {
        return Err(IamStsError::DeleteConflict(format!(
            "role {name} has attached policies and cannot be deleted"
        )));
    }
    store.remove_role(account, name);
    Ok(String::new())
}

// ============================ Managed policies =================================

fn reject_if_aws_managed(policy: &IamPolicy) -> Result<(), IamStsError> {
    if policy.is_aws_managed {
        Err(IamStsError::AccessDenied(
            "AWS-managed policies cannot be modified".into(),
        ))
    } else {
        Ok(())
    }
}

/// Short policy name from a policy ARN (`...:policy<path><name>` → `name`).
fn policy_name_from_arn(arn: &str) -> &str {
    arn.rsplit('/').next().unwrap_or(arn)
}

pub fn create_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("PolicyName")?;
    let document = q.require("PolicyDocument")?.to_string();
    PolicyDocument::parse(&document)?;
    let path = normalize_path(q.get("Path").unwrap_or("/"));
    let arn = build_iam_arn(account, "policy", &path, name);
    let now = now_iso8601();
    let policy = IamPolicy {
        policy_name: name.to_string(),
        policy_id: ids::unique_id(ids::POLICY),
        arn: arn.clone(),
        path,
        create_date: now.clone(),
        default_version_id: "v1".to_string(),
        versions: vec![PolicyVersion {
            version_id: "v1".to_string(),
            document,
            is_default: true,
            create_date: now,
        }],
        attachment_count: 0,
        description: q.get("Description").map(str::to_string),
        tags: tags_map(q.tags("Tags.member")),
        is_aws_managed: false,
    };
    match store.insert_policy(account, policy) {
        Created::Inserted(p) => Ok(p.xml()),
        Created::AlreadyExists => Err(IamStsError::EntityAlreadyExists(format!(
            "policy {name} already exists"
        ))),
    }
}

pub fn get_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let policy = lookup_policy(store, account, arn)?;
    Ok(policy.xml())
}

pub fn list_policies(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let scope = q.get("Scope").unwrap_or("All");
    let want_aws = match scope {
        "All" => None,
        "AWS" => Some(true),
        "Local" => Some(false),
        other => {
            return Err(IamStsError::ValidationError(format!(
                "invalid Scope {other}"
            )))
        }
    };
    let prefix = q.get("PathPrefix");
    let mut policies: Vec<IamPolicy> = store
        .list_policies(account)
        .into_iter()
        .filter(|p| want_aws.map(|w| p.is_aws_managed == w).unwrap_or(true))
        .filter(|p| matches_prefix(&p.path, prefix))
        .collect();
    policies.sort_by(|a, b| a.policy_name.cmp(&b.policy_name));
    let body = members(policies.iter().map(|p| p.member_xml()));
    Ok(format!(
        "<Policies>{body}</Policies><IsTruncated>false</IsTruncated>"
    ))
}

pub fn delete_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let policy = lookup_policy(store, account, arn)?;
    reject_if_aws_managed(&policy)?;
    if policy.attachment_count > 0 {
        return Err(IamStsError::DeleteConflict(format!(
            "policy {arn} is attached and cannot be deleted"
        )));
    }
    store.remove_policy(account, arn);
    Ok(String::new())
}

pub fn tag_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let tags = tags_map(q.tags("Tags.member"));
    lookup_policy(store, account, arn)?;
    store.update_policy(account, arn, |p| p.tags.extend(tags.clone()));
    Ok(String::new())
}

pub fn untag_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let keys = q.list("TagKeys.member");
    lookup_policy(store, account, arn)?;
    store.update_policy(account, arn, |p| p.tags.retain(|k, _| !keys.contains(k)));
    Ok(String::new())
}

pub fn list_policy_tags(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let policy = lookup_policy(store, account, arn)?;
    Ok(format!(
        "{}<IsTruncated>false</IsTruncated>",
        tags_xml(&policy.tags)
    ))
}

fn lookup_policy(store: &IamStore, account: &str, arn: &str) -> Result<IamPolicy, IamStsError> {
    store
        .get_policy(account, arn)
        .or_else(|| store.get_policy("aws", arn))
        .ok_or_else(|| no_such_entity("policy"))
}

// ============================ Policy versions ==================================

pub fn create_policy_version(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let document = q.require("PolicyDocument")?.to_string();
    let set_default = q.get("SetAsDefault").map(|v| v == "true").unwrap_or(false);
    let policy = lookup_policy(store, account, arn)?;
    reject_if_aws_managed(&policy)?;
    if policy.versions.len() >= MAX_POLICY_VERSIONS {
        return Err(IamStsError::LimitExceeded(format!(
            "policy {arn} already has the maximum of {MAX_POLICY_VERSIONS} versions"
        )));
    }
    PolicyDocument::parse(&document)?;
    let next = policy
        .versions
        .iter()
        .filter_map(|v| v.version_id.trim_start_matches('v').parse::<u32>().ok())
        .max()
        .unwrap_or(0)
        + 1;
    let version_id = format!("v{next}");
    let now = now_iso8601();
    let mut result = None;
    store.update_policy(account, arn, |p| {
        if set_default {
            for v in &mut p.versions {
                v.is_default = false;
            }
            p.default_version_id = version_id.clone();
        }
        let version = PolicyVersion {
            version_id: version_id.clone(),
            document: document.clone(),
            is_default: set_default,
            create_date: now.clone(),
        };
        result = Some(version.xml());
        p.versions.push(version);
    });
    Ok(format!(
        "<PolicyVersion>{}</PolicyVersion>",
        strip_member(&result.unwrap_or_default())
    ))
}

pub fn get_policy_version(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let version_id = q.require("VersionId")?;
    let policy = lookup_policy(store, account, arn)?;
    let version = policy
        .versions
        .iter()
        .find(|v| v.version_id == version_id)
        .ok_or_else(|| no_such_entity("policy version"))?;
    Ok(format!(
        "<PolicyVersion>{}</PolicyVersion>",
        strip_member(&version.xml())
    ))
}

pub fn list_policy_versions(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let policy = lookup_policy(store, account, arn)?;
    let body = members(policy.versions.iter().map(|v| v.xml()));
    Ok(format!(
        "<Versions>{body}</Versions><IsTruncated>false</IsTruncated>"
    ))
}

pub fn set_default_policy_version(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let version_id = q.require("VersionId")?.to_string();
    let policy = lookup_policy(store, account, arn)?;
    reject_if_aws_managed(&policy)?;
    if !policy.versions.iter().any(|v| v.version_id == version_id) {
        return Err(no_such_entity("policy version"));
    }
    store.update_policy(account, arn, |p| {
        for v in &mut p.versions {
            v.is_default = v.version_id == version_id;
        }
        p.default_version_id = version_id.clone();
    });
    Ok(String::new())
}

pub fn delete_policy_version(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let arn = q.require("PolicyArn")?;
    let version_id = q.require("VersionId")?;
    let policy = lookup_policy(store, account, arn)?;
    reject_if_aws_managed(&policy)?;
    if policy.default_version_id == version_id {
        return Err(IamStsError::DeleteConflict(
            "the default policy version cannot be deleted".into(),
        ));
    }
    if !policy.versions.iter().any(|v| v.version_id == version_id) {
        return Err(no_such_entity("policy version"));
    }
    store.update_policy(account, arn, |p| {
        p.versions.retain(|v| v.version_id != version_id)
    });
    Ok(String::new())
}

/// Strip the leading `<member>`/trailing `</member>` a [`PolicyVersion::xml`] adds, for use
/// inside a `<PolicyVersion>` element.
fn strip_member(xml: &str) -> String {
    xml.trim_start_matches("<member>")
        .trim_end_matches("</member>")
        .to_string()
}

/// Seed the read-only AWS-managed policy catalog under `arn:aws:iam::aws:policy` (account
/// key `aws`), idempotently. Includes the common Lambda execution-role policies.
pub fn seed_aws_managed_policies(store: &IamStore) {
    const MANAGED: &[&str] = &[
        "AWSLambdaBasicExecutionRole",
        "AWSLambdaVPCAccessExecutionRole",
        "AWSLambdaSQSQueueExecutionRole",
        "AWSLambdaDynamoDBExecutionRole",
        "AWSLambdaKinesisExecutionRole",
    ];
    let now = now_iso8601();
    for name in MANAGED {
        let arn = format!("arn:aws:iam::aws:policy/service-role/{name}");
        let document = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        store.seed_policy(
            "aws",
            IamPolicy {
                policy_name: name.to_string(),
                policy_id: ids::unique_id(ids::POLICY),
                arn: arn.clone(),
                path: "/service-role/".to_string(),
                create_date: now.clone(),
                default_version_id: "v1".to_string(),
                versions: vec![PolicyVersion {
                    version_id: "v1".to_string(),
                    document: document.to_string(),
                    is_default: true,
                    create_date: now.clone(),
                }],
                attachment_count: 0,
                description: Some(format!("AWS managed policy {name}")),
                tags: BTreeMap::new(),
                is_aws_managed: true,
            },
        );
    }
}

// ============================ Attachments & inline =============================

/// IAM principal kind for the polymorphic attach/inline/boundary operations.
#[derive(Debug, Clone, Copy)]
pub enum Entity {
    User,
    Group,
    Role,
}

impl Entity {
    fn name_param(self) -> &'static str {
        match self {
            Entity::User => "UserName",
            Entity::Group => "GroupName",
            Entity::Role => "RoleName",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Entity::User => "user",
            Entity::Group => "group",
            Entity::Role => "role",
        }
    }
}

fn entity_exists(store: &IamStore, account: &str, kind: Entity, name: &str) -> bool {
    match kind {
        Entity::User => store.get_user(account, name).is_some(),
        Entity::Group => store.get_group(account, name).is_some(),
        Entity::Role => store.get_role(account, name).is_some(),
    }
}

fn mutate_attached(
    store: &IamStore,
    account: &str,
    kind: Entity,
    name: &str,
    f: impl FnOnce(&mut Vec<String>),
) -> bool {
    match kind {
        Entity::User => store.update_user(account, name, |u| f(&mut u.attached_policies)),
        Entity::Group => store.update_group(account, name, |g| f(&mut g.attached_policies)),
        Entity::Role => store.update_role(account, name, |r| f(&mut r.attached_policies)),
    }
}

fn read_attached(store: &IamStore, account: &str, kind: Entity, name: &str) -> Option<Vec<String>> {
    match kind {
        Entity::User => store.get_user(account, name).map(|u| u.attached_policies),
        Entity::Group => store.get_group(account, name).map(|g| g.attached_policies),
        Entity::Role => store.get_role(account, name).map(|r| r.attached_policies),
    }
}

fn mutate_inline(
    store: &IamStore,
    account: &str,
    kind: Entity,
    name: &str,
    f: impl FnOnce(&mut BTreeMap<String, String>),
) -> bool {
    match kind {
        Entity::User => store.update_user(account, name, |u| f(&mut u.inline_policies)),
        Entity::Group => store.update_group(account, name, |g| f(&mut g.inline_policies)),
        Entity::Role => store.update_role(account, name, |r| f(&mut r.inline_policies)),
    }
}

fn read_inline(
    store: &IamStore,
    account: &str,
    kind: Entity,
    name: &str,
) -> Option<BTreeMap<String, String>> {
    match kind {
        Entity::User => store.get_user(account, name).map(|u| u.inline_policies),
        Entity::Group => store.get_group(account, name).map(|g| g.inline_policies),
        Entity::Role => store.get_role(account, name).map(|r| r.inline_policies),
    }
}

pub fn attach_policy(store: &IamStore, account: &str, kind: Entity, q: &QueryRequest) -> OpResult {
    let name = q.require(kind.name_param())?;
    let policy_arn = q.require("PolicyArn")?;
    lookup_policy(store, account, policy_arn)?;
    if !entity_exists(store, account, kind, name) {
        return Err(no_such_entity(kind.label()));
    }
    let mut newly_attached = false;
    mutate_attached(store, account, kind, name, |list| {
        if !list.iter().any(|a| a == policy_arn) {
            list.push(policy_arn.to_string());
            newly_attached = true;
        }
    });
    if newly_attached && store.get_policy(account, policy_arn).is_some() {
        store.update_policy(account, policy_arn, |p| p.attachment_count += 1);
    }
    Ok(String::new())
}

pub fn detach_policy(store: &IamStore, account: &str, kind: Entity, q: &QueryRequest) -> OpResult {
    let name = q.require(kind.name_param())?;
    let policy_arn = q.require("PolicyArn")?;
    let attached =
        read_attached(store, account, kind, name).ok_or_else(|| no_such_entity(kind.label()))?;
    if !attached.iter().any(|a| a == policy_arn) {
        return Err(no_such_entity("attached policy"));
    }
    mutate_attached(store, account, kind, name, |list| {
        list.retain(|a| a != policy_arn)
    });
    if store.get_policy(account, policy_arn).is_some() {
        store.update_policy(account, policy_arn, |p| {
            p.attachment_count = p.attachment_count.saturating_sub(1)
        });
    }
    Ok(String::new())
}

pub fn list_attached_policies(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let attached =
        read_attached(store, account, kind, name).ok_or_else(|| no_such_entity(kind.label()))?;
    let body = members(attached.iter().map(|arn| {
        format!(
            "<member>{}{}</member>",
            text_el("PolicyName", policy_name_from_arn(arn)),
            text_el("PolicyArn", arn)
        )
    }));
    Ok(format!(
        "<AttachedPolicies>{body}</AttachedPolicies><IsTruncated>false</IsTruncated>"
    ))
}

pub fn put_inline_policy(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let policy_name = q.require("PolicyName")?.to_string();
    let document = q.require("PolicyDocument")?.to_string();
    if !entity_exists(store, account, kind, name) {
        return Err(no_such_entity(kind.label()));
    }
    PolicyDocument::parse(&document)?;
    if !mutate_inline(store, account, kind, name, |policies| {
        policies.insert(policy_name, document);
    }) {
        return Err(no_such_entity(kind.label()));
    }
    Ok(String::new())
}

pub fn get_inline_policy(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let policy_name = q.require("PolicyName")?;
    let inline =
        read_inline(store, account, kind, name).ok_or_else(|| no_such_entity(kind.label()))?;
    let document = inline
        .get(policy_name)
        .ok_or_else(|| no_such_entity("inline policy"))?;
    Ok(format!(
        "{}{}<PolicyDocument>{}</PolicyDocument>",
        text_el(entity_name_tag(kind), name),
        text_el("PolicyName", policy_name),
        xml_escape(&urlencode_doc(document)),
    ))
}

pub fn list_inline_policies(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let inline =
        read_inline(store, account, kind, name).ok_or_else(|| no_such_entity(kind.label()))?;
    let body = members(inline.keys().map(|n| text_el("member", n)));
    Ok(format!(
        "<PolicyNames>{body}</PolicyNames><IsTruncated>false</IsTruncated>"
    ))
}

pub fn delete_inline_policy(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let policy_name = q.require("PolicyName")?;
    let inline =
        read_inline(store, account, kind, name).ok_or_else(|| no_such_entity(kind.label()))?;
    if !inline.contains_key(policy_name) {
        return Err(no_such_entity("inline policy"));
    }
    mutate_inline(store, account, kind, name, |m| {
        m.remove(policy_name);
    });
    Ok(String::new())
}

fn entity_name_tag(kind: Entity) -> &'static str {
    match kind {
        Entity::User => "UserName",
        Entity::Group => "GroupName",
        Entity::Role => "RoleName",
    }
}

// ============================ Permission boundaries ============================

pub fn put_permissions_boundary(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let boundary = q.require("PermissionsBoundary")?.to_string();
    lookup_policy(store, account, &boundary)?;
    let updated = match kind {
        Entity::User => {
            store.update_user(account, name, |u| u.permission_boundary = Some(boundary))
        }
        Entity::Role => {
            store.update_role(account, name, |r| r.permission_boundary = Some(boundary))
        }
        Entity::Group => {
            return Err(IamStsError::ValidationError(
                "groups do not support permission boundaries".into(),
            ))
        }
    };
    if !updated {
        return Err(no_such_entity(kind.label()));
    }
    Ok(String::new())
}

pub fn delete_permissions_boundary(
    store: &IamStore,
    account: &str,
    kind: Entity,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require(kind.name_param())?;
    let updated = match kind {
        Entity::User => store.update_user(account, name, |u| u.permission_boundary = None),
        Entity::Role => store.update_role(account, name, |r| r.permission_boundary = None),
        Entity::Group => {
            return Err(IamStsError::ValidationError(
                "groups do not support permission boundaries".into(),
            ))
        }
    };
    if !updated {
        return Err(no_such_entity(kind.label()));
    }
    Ok(String::new())
}

// ============================ Access keys ======================================

pub fn create_access_key(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let user_name = q.require("UserName")?;
    let user = store
        .get_user(account, user_name)
        .ok_or_else(|| no_such_entity("user"))?;
    if user.access_keys.len() >= MAX_ACCESS_KEYS {
        return Err(IamStsError::LimitExceeded(format!(
            "user {user_name} already has the maximum of {MAX_ACCESS_KEYS} access keys"
        )));
    }
    let key = AccessKey {
        access_key_id: ids::unique_id(ids::ACCESS_KEY),
        secret_access_key: ids::secret_access_key(),
        status: "Active".to_string(),
        create_date: now_iso8601(),
    };
    let result = format!(
        "<AccessKey>{}{}{}{}{}</AccessKey>",
        text_el("UserName", user_name),
        text_el("AccessKeyId", &key.access_key_id),
        text_el("Status", &key.status),
        text_el("SecretAccessKey", &key.secret_access_key),
        text_el("CreateDate", &key.create_date),
    );
    store.update_user(account, user_name, |u| u.access_keys.push(key));
    Ok(result)
}

pub fn list_access_keys(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let user_name = q.require("UserName")?;
    let user = store
        .get_user(account, user_name)
        .ok_or_else(|| no_such_entity("user"))?;
    let body = members(user.access_keys.iter().map(|k| {
        format!(
            "<member>{}{}{}{}</member>",
            text_el("UserName", user_name),
            text_el("AccessKeyId", &k.access_key_id),
            text_el("Status", &k.status),
            text_el("CreateDate", &k.create_date),
        )
    }));
    Ok(format!(
        "<AccessKeyMetadata>{body}</AccessKeyMetadata><IsTruncated>false</IsTruncated>"
    ))
}

pub fn update_access_key(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let user_name = q.require("UserName")?;
    let key_id = q.require("AccessKeyId")?;
    let status = q.require("Status")?;
    if status != "Active" && status != "Inactive" {
        return Err(IamStsError::ValidationError(format!(
            "invalid Status {status}"
        )));
    }
    let user = store
        .get_user(account, user_name)
        .ok_or_else(|| no_such_entity("user"))?;
    if !user.access_keys.iter().any(|k| k.access_key_id == key_id) {
        return Err(no_such_entity("access key"));
    }
    store.update_user(account, user_name, |u| {
        if let Some(k) = u.access_keys.iter_mut().find(|k| k.access_key_id == key_id) {
            k.status = status.to_string();
        }
    });
    Ok(String::new())
}

pub fn delete_access_key(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let user_name = q.require("UserName")?;
    let key_id = q.require("AccessKeyId")?;
    let user = store
        .get_user(account, user_name)
        .ok_or_else(|| no_such_entity("user"))?;
    if !user.access_keys.iter().any(|k| k.access_key_id == key_id) {
        return Err(no_such_entity("access key"));
    }
    store.update_user(account, user_name, |u| {
        u.access_keys.retain(|k| k.access_key_id != key_id)
    });
    Ok(String::new())
}

// ============================ Instance profiles ================================

fn instance_profile_fields(store: &IamStore, account: &str, profile: &InstanceProfile) -> String {
    // InstanceProfile.Roles is a list whose entries are wrapped in <member>.
    let roles = match &profile.role {
        Some(name) => store
            .get_role(account, name)
            .map(|r| r.member_xml())
            .unwrap_or_default(),
        None => String::new(),
    };
    format!(
        "{}{}{}{}{}<Roles>{}</Roles>",
        text_el("Path", &profile.path),
        text_el("InstanceProfileName", &profile.name),
        text_el("InstanceProfileId", &profile.id),
        text_el("Arn", &profile.arn),
        text_el("CreateDate", &profile.create_date),
        roles,
    )
}

fn instance_profile_xml(store: &IamStore, account: &str, profile: &InstanceProfile) -> String {
    format!(
        "<InstanceProfile>{}</InstanceProfile>",
        instance_profile_fields(store, account, profile)
    )
}

fn instance_profile_member(store: &IamStore, account: &str, profile: &InstanceProfile) -> String {
    format!(
        "<member>{}</member>",
        instance_profile_fields(store, account, profile)
    )
}

pub fn create_instance_profile(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("InstanceProfileName")?;
    let path = normalize_path(q.get("Path").unwrap_or("/"));
    let profile = InstanceProfile {
        name: name.to_string(),
        id: ids::unique_id(ids::INSTANCE_PROFILE),
        arn: build_iam_arn(account, "instance-profile", &path, name),
        path,
        create_date: now_iso8601(),
        role: None,
    };
    match store.create_instance_profile(account, profile.clone()) {
        Created::Inserted(_) => Ok(instance_profile_xml(store, account, &profile)),
        Created::AlreadyExists => Err(IamStsError::EntityAlreadyExists(format!(
            "instance profile {name} already exists"
        ))),
    }
}

pub fn get_instance_profile(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("InstanceProfileName")?;
    let profile = store
        .get_instance_profile(account, name)
        .ok_or_else(|| no_such_entity("instance profile"))?;
    Ok(instance_profile_xml(store, account, &profile))
}

pub fn list_instance_profiles(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let prefix = q.get("PathPrefix");
    let mut profiles: Vec<InstanceProfile> = store
        .list_instance_profiles(account)
        .into_iter()
        .filter(|p| matches_prefix(&p.path, prefix))
        .collect();
    profiles.sort_by(|a, b| a.name.cmp(&b.name));
    let body = members(
        profiles
            .iter()
            .map(|p| instance_profile_member(store, account, p)),
    );
    Ok(format!(
        "<InstanceProfiles>{body}</InstanceProfiles><IsTruncated>false</IsTruncated>"
    ))
}

pub fn add_role_to_instance_profile(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("InstanceProfileName")?;
    let role_name = q.require("RoleName")?;
    let profile = store
        .get_instance_profile(account, name)
        .ok_or_else(|| no_such_entity("instance profile"))?;
    if store.get_role(account, role_name).is_none() {
        return Err(no_such_entity("role"));
    }
    if profile.role.is_some() {
        return Err(IamStsError::LimitExceeded(format!(
            "instance profile {name} already has a role"
        )));
    }
    store.update_instance_profile(account, name, |p| p.role = Some(role_name.to_string()));
    Ok(String::new())
}

pub fn remove_role_from_instance_profile(
    store: &IamStore,
    account: &str,
    q: &QueryRequest,
) -> OpResult {
    let name = q.require("InstanceProfileName")?;
    let _role_name = q.require("RoleName")?;
    if store.get_instance_profile(account, name).is_none() {
        return Err(no_such_entity("instance profile"));
    }
    store.update_instance_profile(account, name, |p| p.role = None);
    Ok(String::new())
}

pub fn list_instance_profiles_for_role(
    store: &IamStore,
    account: &str,
    q: &QueryRequest,
) -> OpResult {
    let role_name = q.require("RoleName")?;
    if store.get_role(account, role_name).is_none() {
        return Err(no_such_entity("role"));
    }
    let profiles: Vec<InstanceProfile> = store
        .list_instance_profiles(account)
        .into_iter()
        .filter(|p| p.role.as_deref() == Some(role_name))
        .collect();
    let body = members(
        profiles
            .iter()
            .map(|p| instance_profile_member(store, account, p)),
    );
    Ok(format!(
        "<InstanceProfiles>{body}</InstanceProfiles><IsTruncated>false</IsTruncated>"
    ))
}

pub fn delete_instance_profile(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let name = q.require("InstanceProfileName")?;
    let profile = store
        .get_instance_profile(account, name)
        .ok_or_else(|| no_such_entity("instance profile"))?;
    if profile.role.is_some() {
        return Err(IamStsError::DeleteConflict(format!(
            "instance profile {name} has an associated role"
        )));
    }
    store.remove_instance_profile(account, name);
    Ok(String::new())
}

// ============================ Simulate APIs ====================================

/// Parse `ContextEntries.member.N` into a lowercased condition context.
fn parse_context_entries(q: &QueryRequest) -> BTreeMap<String, Vec<String>> {
    let mut context = BTreeMap::new();
    let mut n = 1usize;
    loop {
        let key = q.get(&format!("ContextEntries.member.{n}.ContextKeyName"));
        match key {
            Some(k) => {
                let values = q.list(&format!(
                    "ContextEntries.member.{n}.ContextKeyValues.member"
                ));
                context.insert(k.to_ascii_lowercase(), values);
                n += 1;
            }
            None => break,
        }
    }
    context
}

fn eval_decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allowed => "allowed",
        Decision::ImplicitDeny => "implicitDeny",
        Decision::ExplicitDeny => "explicitDeny",
    }
}

fn simulate(documents: &[PolicyDocument], q: &QueryRequest) -> OpResult {
    let actions = q.list("ActionNames.member");
    if actions.is_empty() {
        return Err(IamStsError::ValidationError(
            "ActionNames is required".into(),
        ));
    }
    let mut resources = q.list("ResourceArns.member");
    if resources.is_empty() {
        resources.push("*".to_string());
    }
    let context = parse_context_entries(q);
    let mut results = String::new();
    for action in &actions {
        for resource in &resources {
            let req = EvalRequest {
                action: action.clone(),
                resource: resource.clone(),
                context: context.clone(),
            };
            let decision = evaluate(documents, None, None, &req);
            results.push_str(&format!(
                "<member>{}{}{}<MatchedStatements/><MissingContextValues/></member>",
                text_el("EvalActionName", action),
                text_el("EvalResourceName", resource),
                text_el("EvalDecision", eval_decision_str(decision)),
            ));
        }
    }
    Ok(format!(
        "<EvaluationResults>{results}</EvaluationResults><IsTruncated>false</IsTruncated>"
    ))
}

pub fn simulate_custom_policy(_store: &IamStore, _account: &str, q: &QueryRequest) -> OpResult {
    let inputs = q.list("PolicyInputList.member");
    let mut documents = Vec::with_capacity(inputs.len());
    for doc in &inputs {
        documents.push(PolicyDocument::parse(doc)?);
    }
    simulate(&documents, q)
}

pub fn simulate_principal_policy(store: &IamStore, account: &str, q: &QueryRequest) -> OpResult {
    let source_arn = q.require("PolicySourceArn")?;
    let principal_name = source_arn.rsplit('/').next().unwrap_or(source_arn);
    let mut documents = principal_policy_documents(store, account, source_arn, principal_name)?;
    for doc in q.list("PolicyInputList.member") {
        documents.push(PolicyDocument::parse(&doc)?);
    }
    simulate(&documents, q)
}

/// Gather the inline + attached managed policy documents for a user or role principal.
fn principal_policy_documents(
    store: &IamStore,
    account: &str,
    source_arn: &str,
    name: &str,
) -> Result<Vec<PolicyDocument>, IamStsError> {
    let (inline, attached): (BTreeMap<String, String>, Vec<String>) =
        if source_arn.contains(":role/") {
            let role = store
                .get_role(account, name)
                .ok_or_else(|| no_such_entity("role"))?;
            (role.inline_policies, role.attached_policies)
        } else {
            let user = store
                .get_user(account, name)
                .ok_or_else(|| no_such_entity("user"))?;
            (user.inline_policies, user.attached_policies)
        };
    let mut documents = Vec::new();
    for doc in inline.values() {
        documents.push(PolicyDocument::parse(doc)?);
    }
    for arn in &attached {
        if let Some(policy) = store
            .get_policy(account, arn)
            .or_else(|| store.get_policy("aws", arn))
        {
            if let Some(version) = policy.default_version() {
                documents.push(PolicyDocument::parse(&version.document)?);
            }
        }
    }
    Ok(documents)
}
