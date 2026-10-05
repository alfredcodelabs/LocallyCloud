//! IAM resource model and XML serialization fragments.
//!
//! Each struct serializes to the inner XML AWS returns for that resource (without the
//! `<{Action}Result>` wrapper, which the Query layer adds). Timestamps are ISO-8601 UTC.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::query::{text_el, xml_escape};

/// Current UTC time as an ISO-8601 (RFC-3339) string, e.g. `2015-03-21T20:23:17Z`.
pub fn now_iso8601() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Serialize a tag list as `<Tags><member><Key>..</Key><Value>..</Value></member>...</Tags>`.
pub fn tags_xml(tags: &BTreeMap<String, String>) -> String {
    if tags.is_empty() {
        return String::new();
    }
    let members: String = tags
        .iter()
        .map(|(k, v)| {
            format!(
                "<member>{}{}</member>",
                text_el("Key", k),
                text_el("Value", v)
            )
        })
        .collect();
    format!("<Tags>{members}</Tags>")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamUser {
    pub user_name: String,
    pub user_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: String,
    pub tags: BTreeMap<String, String>,
    pub attached_policies: Vec<String>,
    pub inline_policies: BTreeMap<String, String>,
    pub groups: Vec<String>,
    pub permission_boundary: Option<String>,
    pub access_keys: Vec<AccessKey>,
}

impl IamUser {
    fn fields(&self) -> String {
        format!(
            "{}{}{}{}{}",
            text_el("Path", &self.path),
            text_el("UserName", &self.user_name),
            text_el("UserId", &self.user_id),
            text_el("Arn", &self.arn),
            text_el("CreateDate", &self.create_date),
        )
    }
    pub fn xml(&self) -> String {
        format!("<User>{}</User>", self.fields())
    }
    pub fn member_xml(&self) -> String {
        format!("<member>{}</member>", self.fields())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamGroup {
    pub group_name: String,
    pub group_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: String,
    pub members: Vec<String>,
    pub attached_policies: Vec<String>,
    pub inline_policies: BTreeMap<String, String>,
}

impl IamGroup {
    fn fields(&self) -> String {
        format!(
            "{}{}{}{}{}",
            text_el("Path", &self.path),
            text_el("GroupName", &self.group_name),
            text_el("GroupId", &self.group_id),
            text_el("Arn", &self.arn),
            text_el("CreateDate", &self.create_date),
        )
    }
    pub fn xml(&self) -> String {
        format!("<Group>{}</Group>", self.fields())
    }
    pub fn member_xml(&self) -> String {
        format!("<member>{}</member>", self.fields())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamRole {
    pub role_name: String,
    pub role_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: String,
    pub assume_role_policy_document: String,
    pub description: Option<String>,
    pub max_session_duration: u32,
    pub tags: BTreeMap<String, String>,
    pub attached_policies: Vec<String>,
    pub inline_policies: BTreeMap<String, String>,
    pub permission_boundary: Option<String>,
}

impl IamRole {
    fn fields(&self) -> String {
        let description = self
            .description
            .as_ref()
            .map(|d| text_el("Description", d))
            .unwrap_or_default();
        format!(
            "{}{}{}{}{}<AssumeRolePolicyDocument>{}</AssumeRolePolicyDocument>{}<MaxSessionDuration>{}</MaxSessionDuration>{}",
            text_el("Path", &self.path),
            text_el("RoleName", &self.role_name),
            text_el("RoleId", &self.role_id),
            text_el("Arn", &self.arn),
            text_el("CreateDate", &self.create_date),
            xml_escape(&urlencode_doc(&self.assume_role_policy_document)),
            description,
            self.max_session_duration,
            tags_xml(&self.tags),
        )
    }
    pub fn xml(&self) -> String {
        format!("<Role>{}</Role>", self.fields())
    }
    pub fn member_xml(&self) -> String {
        format!("<member>{}</member>", self.fields())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IamPolicy {
    pub policy_name: String,
    pub policy_id: String,
    pub arn: String,
    pub path: String,
    pub create_date: String,
    pub default_version_id: String,
    pub versions: Vec<PolicyVersion>,
    pub attachment_count: u32,
    pub description: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub is_aws_managed: bool,
}

impl IamPolicy {
    fn fields(&self) -> String {
        let description = self
            .description
            .as_ref()
            .map(|d| text_el("Description", d))
            .unwrap_or_default();
        format!(
            "{}{}{}{}<DefaultVersionId>{}</DefaultVersionId><AttachmentCount>{}</AttachmentCount>{}{}{}",
            text_el("PolicyName", &self.policy_name),
            text_el("PolicyId", &self.policy_id),
            text_el("Arn", &self.arn),
            text_el("Path", &self.path),
            xml_escape(&self.default_version_id),
            self.attachment_count,
            description,
            text_el("CreateDate", &self.create_date),
            tags_xml(&self.tags),
        )
    }
    pub fn xml(&self) -> String {
        format!("<Policy>{}</Policy>", self.fields())
    }
    pub fn member_xml(&self) -> String {
        format!("<member>{}</member>", self.fields())
    }

    pub fn default_version(&self) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .find(|v| v.version_id == self.default_version_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    pub version_id: String,
    pub document: String,
    pub is_default: bool,
    pub create_date: String,
}

impl PolicyVersion {
    pub fn xml(&self) -> String {
        format!(
            "<member><Document>{}</Document>{}<IsDefaultVersion>{}</IsDefaultVersion>{}</member>",
            xml_escape(&urlencode_doc(&self.document)),
            text_el("VersionId", &self.version_id),
            self.is_default,
            text_el("CreateDate", &self.create_date),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKey {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub status: String,
    pub create_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceProfile {
    pub name: String,
    pub id: String,
    pub arn: String,
    pub path: String,
    pub create_date: String,
    pub role: Option<String>,
}

/// AWS returns policy documents URL-encoded in Query responses. Mirror that so SDKs that
/// URL-decode the field recover the original JSON.
pub fn urlencode_doc(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    for b in doc.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_is_rfc3339() {
        let now = now_iso8601();
        assert!(now.contains('T'));
        assert!(now.ends_with('Z') || now.contains('+'));
    }

    #[test]
    fn urlencode_doc_escapes_json_punctuation() {
        let enc = urlencode_doc("{\"a\":\"b\"}");
        assert_eq!(enc, "%7B%22a%22%3A%22b%22%7D");
    }

    #[test]
    fn tags_xml_empty_is_blank() {
        assert_eq!(tags_xml(&BTreeMap::new()), "");
    }

    #[test]
    fn list_member_wraps_in_member_not_entity() {
        let user = IamUser {
            user_name: "alice".into(),
            user_id: "AIDA1".into(),
            arn: "arn:aws:iam::1:user/alice".into(),
            path: "/".into(),
            create_date: "now".into(),
            tags: BTreeMap::new(),
            attached_policies: vec![],
            inline_policies: BTreeMap::new(),
            groups: vec![],
            permission_boundary: None,
            access_keys: vec![],
        };
        assert!(user.xml().starts_with("<User>"));
        assert!(user.member_xml().starts_with("<member>"));
        assert!(user.member_xml().contains("<UserName>alice</UserName>"));
        assert!(!user.member_xml().contains("<User>"));
    }
}
