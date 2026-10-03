//! Server-held local AWS profiles and read-only dashboard requests.
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::integration::authorization::SigningCredentials;

pub(crate) struct Profile {
    pub name: String,
    pub region: String,
    pub access_key: Option<String>,
    pub credentials: Option<SigningCredentials>,
}

pub(crate) struct DashboardContext {
    pub profiles: Vec<Profile>,
    pub account_id: String,
    pub default_region: String,
    listen_addr: SocketAddr,
}

// Only static profiles explicitly targeting this local instance are eligible. Never
// execute credential_process, resolve SSO, or load cloud profiles into this dashboard.
impl DashboardContext {
    pub async fn load(addr: SocketAddr, account_id: String, default_region: String) -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        let config = std::env::var_os("AWS_CONFIG_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".aws/config"));
        let credentials = std::env::var_os("AWS_SHARED_CREDENTIALS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".aws/credentials"));
        let (config, credentials) = tokio::join!(read_ini(config), read_ini(credentials));
        let mut profiles = vec![Profile {
            name: "instance".into(),
            region: default_region.clone(),
            access_key: None,
            credentials: None,
        }];
        for (section, values) in config {
            if !addr.ip().is_loopback() {
                break;
            }
            let name = if section == "default" {
                "default"
            } else if let Some(name) = section.strip_prefix("profile ") {
                name
            } else {
                continue;
            };
            if name == "instance" || name.is_empty() || name.len() > 128 {
                continue;
            }
            let Some(endpoint) = values.get("endpoint_url") else {
                continue;
            };
            if !local_endpoint(endpoint, addr) {
                continue;
            }
            let Some(keys) = credentials.get(name) else {
                continue;
            };
            let (Some(access), Some(secret)) = (
                keys.get("aws_access_key_id"),
                keys.get("aws_secret_access_key"),
            ) else {
                continue;
            };
            if access.is_empty() || secret.is_empty() {
                continue;
            }
            let region = values
                .get("region")
                .filter(|region| valid_region(region))
                .cloned()
                .unwrap_or_else(|| default_region.clone());
            profiles.push(Profile {
                name: name.into(),
                region,
                access_key: Some(access.clone()),
                credentials: Some(SigningCredentials {
                    secret_access_key: secret.clone(),
                    session_token: keys.get("aws_session_token").cloned(),
                }),
            });
        }
        Self {
            profiles,
            account_id,
            default_region,
            listen_addr: addr,
        }
    }

    // OS file caching keeps these small local configuration reads cheap. Refreshing
    // here also picks up rotated credentials and STS session tokens without a restart.
    pub async fn refreshed(&self) -> Self {
        Self::load(
            self.listen_addr,
            self.account_id.clone(),
            self.default_region.clone(),
        )
        .await
    }

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|profile| profile.name == name)
    }
}

pub(crate) fn valid_region(region: &str) -> bool {
    region.len() <= 32
        && region.split('-').count() >= 3
        && region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && region.as_bytes().last().is_some_and(u8::is_ascii_digit)
        && !region.contains("--")
        && !region.starts_with('-')
}

fn local_endpoint(endpoint: &str, addr: SocketAddr) -> bool {
    let Ok(uri) = endpoint.parse::<http::Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("http")
        && uri.port_u16().unwrap_or(80) == addr.port()
        && uri.path() == "/"
        && uri.query().is_none()
        && uri.host().is_some_and(|host| {
            host == "localhost"
                || host == "127.0.0.1"
                || host == "[::1]"
                || host == addr.ip().to_string()
        })
}

type Ini = BTreeMap<String, BTreeMap<String, String>>;
async fn read_ini(path: PathBuf) -> Ini {
    if !tokio::fs::metadata(&path)
        .await
        .is_ok_and(|meta| meta.len() <= 1024 * 1024)
    {
        return Ini::new();
    }
    tokio::fs::read_to_string(path)
        .await
        .map(|text| parse_ini(&text))
        .unwrap_or_default()
}
fn parse_ini(text: &str) -> Ini {
    let mut result = Ini::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            section = name.trim().into();
        } else if let Some((key, value)) = line.split_once('=') {
            result
                .entry(section.clone())
                .or_default()
                .insert(key.trim().into(), value.trim().into());
        }
    }
    result
}

/// Explicit allowlist: the dashboard cannot use profile credentials to mutate resources
/// or read SSM/Secrets Manager/KMS plaintext. Service routing is derived server-side.
pub(crate) fn read_target(service: &str, operation: &str) -> Option<(&'static str, &'static str)> {
    match (service, operation) {
        ("dynamodb", "ListTables" | "DescribeTable" | "Scan" | "Query") => {
            Some(("DynamoDB_20120810", "1.0"))
        }
        ("logs", "DescribeLogGroups" | "DescribeLogStreams" | "FilterLogEvents") => {
            Some(("Logs_20140328", "1.1"))
        }
        ("monitoring", "GetMetricStatistics") => Some(("GraniteServiceVersion20100801", "1.0")),
        (
            "states",
            "ListStateMachines"
            | "DescribeStateMachine"
            | "ListExecutions"
            | "DescribeExecution"
            | "GetExecutionHistory",
        ) => Some(("AWSStepFunctions", "1.0")),
        (
            "sqs",
            "ListQueues" | "GetQueueUrl" | "GetQueueAttributes" | "ListDeadLetterSourceQueues",
        ) => Some(("AmazonSQS", "1.0")),
        (
            "events",
            "ListEventBuses" | "DescribeEventBus" | "ListRules" | "DescribeRule"
            | "ListTargetsByRule" | "ListArchives" | "DescribeArchive" | "ListReplays"
            | "DescribeReplay",
        ) => Some(("AWSEvents", "1.1")),
        _ => None,
    }
}

pub(crate) fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

pub(crate) fn query_read(
    service: &str,
    operation: &str,
    body: &serde_json::Value,
) -> Result<String, &'static str> {
    let (version, fields): (&str, &[&str]) = match (service, operation) {
        ("sns", "ListTopics") => ("2010-03-31", &["NextToken"]),
        ("sns", "GetTopicAttributes") => ("2010-03-31", &["TopicArn"]),
        ("sns", "ListSubscriptionsByTopic") => ("2010-03-31", &["TopicArn", "NextToken"]),
        ("sns", "GetSubscriptionAttributes") => ("2010-03-31", &["SubscriptionArn"]),
        ("cloudformation", "DescribeStacks" | "DescribeStackEvents") => {
            ("2010-05-15", &["StackName", "NextToken"])
        }
        ("cloudformation", "DescribeStackResources") => ("2010-05-15", &["StackName"]),
        _ => return Err("unsupported dashboard Query read"),
    };
    let map = body
        .as_object()
        .ok_or("Query parameters must be an object")?;
    let mut encoded = format!("Action={operation}&Version={version}");
    for (key, value) in map {
        if value.is_null() {
            continue;
        }
        if !fields.contains(&key.as_str()) {
            return Err("unsupported Query parameter");
        }
        let value = value.as_str().ok_or("Query parameters must be strings")?;
        encoded.push_str(&format!("&{key}={}", encode(value)));
    }
    Ok(encoded)
}

pub(crate) fn rest_read(service: &str, path: &str) -> Result<http::Uri, &'static str> {
    let uri: http::Uri = path.parse().map_err(|_| "invalid read path")?;
    if !path.starts_with('/') || uri.authority().is_some() || uri.scheme().is_some() {
        return Err("dashboard read must use a local path");
    }
    let parts: Vec<_> = uri.path().trim_start_matches('/').split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err("invalid resource path");
    }
    let allowed = matches!(
        (service, parts.as_slice()),
        (
            "apigateway",
            ["restapis"] | ["restapis", _] | ["v2", "apis"] | ["v2", "apis", _]
        ) | (
            "apigateway",
            ["restapis", _, "resources" | "stages" | "deployments"]
        ) | ("apigateway", ["restapis", _, "stages", _])
            | ("apigateway", ["restapis", _, "resources", _, "methods", _])
            | (
                "apigateway",
                ["restapis", _, "resources", _, "methods", _, "integration"]
            )
            | (
                "apigateway",
                ["v2", "apis", _, "routes" | "integrations" | "stages"]
            )
            | (
                "apigateway",
                ["v2", "apis", _, "routes" | "integrations" | "stages", _]
            )
            | (
                "scheduler",
                ["schedules" | "schedule-groups"] | ["schedules" | "schedule-groups", _]
            )
            | ("pipes", ["v1", "pipes"] | ["v1", "pipes", _])
    );
    if !allowed {
        return Err("unsupported dashboard REST read");
    }
    for pair in uri
        .query()
        .unwrap_or("")
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let key = pair.split('=').next().unwrap_or("");
        let valid = match service {
            "apigateway" => matches!(key, "position" | "limit" | "nextToken" | "maxResults"),
            "scheduler" => matches!(key, "NextToken" | "MaxResults" | "GroupName" | "groupName"),
            "pipes" => matches!(key, "NextToken" | "Limit"),
            _ => false,
        };
        if !valid {
            return Err("unsupported dashboard REST query");
        }
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_profiles_and_read_boundary() {
        let addr = "127.0.0.1:4566".parse().unwrap();
        assert!(local_endpoint("http://localhost:4566", addr));
        assert!(!local_endpoint("https://s3.amazonaws.com", addr));
        assert!(!local_endpoint("http://localhost:4567", addr));
        assert!(!local_endpoint("http://localhost:4566/path", addr));
        assert!(valid_region("us-west-2"));
        assert!(valid_region("us-gov-east-1"));
        assert!(!valid_region("../../us-east-1"));
        assert!(read_target("dynamodb", "Scan").is_some());
        assert!(read_target("dynamodb", "DeleteTable").is_none());
        assert!(read_target("secretsmanager", "GetSecretValue").is_none());
        assert!(read_target("events", "ListTargetsByRule").is_some());
        assert!(read_target("events", "PutTargets").is_none());
        assert!(query_read(
            "sns",
            "ListTopics",
            &serde_json::json!({"NextToken":"a&Action=Publish"})
        )
        .unwrap()
        .contains("a%26Action%3DPublish"));
        assert!(query_read("sns", "Publish", &serde_json::json!({})).is_err());
        assert!(query_read(
            "sns",
            "ListTopics",
            &serde_json::json!({"Action":"Publish"})
        )
        .is_err());
        assert!(rest_read("apigateway", "/v2/apis/api/routes?nextToken=a%26b").is_ok());
        assert!(rest_read("apigateway", "/apikeys?includeValues=true").is_err());
        assert!(rest_read("apigateway", "/restapis/id/stage/_user_request_/path").is_err());
        assert!(rest_read("pipes", "/v1/pipes/orders/start").is_err());
        assert!(rest_read("apigateway", "http://example.com/v2/apis").is_err());
        let ini =
            parse_ini("[profile dev]\nregion = us-west-2\nendpoint_url=http://localhost:4566\n");
        assert_eq!(ini["profile dev"]["region"], "us-west-2");
    }
}
