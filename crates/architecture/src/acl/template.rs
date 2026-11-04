//! Declarations and dependency references of the processed template.
//!
//! The template is only used for provisioning dependencies, undeployed conditional resources
//! and, where a deployed read cannot name a resource, to pick candidates that a deployed read
//! then verifies. Its property values never leave this module's callers.

use std::collections::HashMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::domain::{EdgeKind, Finding};

pub(crate) struct Declaration<'t> {
    pub logical_id: &'t str,
    pub resource_type: Option<&'t str>,
    pub conditional: bool,
}

pub(crate) struct TemplateView<'t> {
    resources: &'t Map<String, Value>,
}

impl<'t> TemplateView<'t> {
    pub(crate) fn new(template: &'t Value) -> Option<Self> {
        template
            .get("Resources")
            .and_then(Value::as_object)
            .map(|resources| Self { resources })
    }

    pub(crate) fn declarations(&self) -> impl Iterator<Item = Declaration<'t>> + 't {
        self.resources
            .iter()
            .map(|(logical_id, resource)| Declaration {
                logical_id,
                resource_type: resource.get("Type").and_then(Value::as_str),
                conditional: resource.get("Condition").is_some(),
            })
    }

    pub(crate) fn property(&self, logical_id: &str, name: &str) -> Option<&'t Value> {
        self.resources.get(logical_id)?.get("Properties")?.get(name)
    }

    pub(crate) fn properties(&self, logical_id: &str) -> Option<&'t Value> {
        self.resources.get(logical_id)?.get("Properties")
    }

    pub(crate) fn of_type<'s>(
        &'s self,
        resource_type: &'s str,
    ) -> impl Iterator<Item = (&'t str, &'t Value)> + 's {
        self.resources
            .iter()
            .filter_map(move |(logical_id, resource)| {
                (resource.get("Type").and_then(Value::as_str) == Some(resource_type))
                    .then(|| Some((logical_id.as_str(), resource.get("Properties")?)))
                    .flatten()
            })
    }

    pub(crate) fn mentions(&self, value: &Value, logical_id: &str) -> bool {
        references(value, self.resources).contains(&logical_id)
    }

    pub(crate) fn referenced(&self, value: &'t Value) -> Vec<&'t str> {
        references(value, self.resources)
    }

    pub(crate) fn config_hash(&self, logical_id: &str, physical_id: &str) -> Option<String> {
        let resource = self.resources.get(logical_id)?;
        let mut canonical = String::new();
        canonical.push_str(resource.get("Type").and_then(Value::as_str).unwrap_or(""));
        canonical.push('\n');
        canonical.push_str(physical_id);
        canonical.push('\n');
        if let Some(properties) = resource.get("Properties") {
            write_canonical(properties, "", 0, &mut canonical);
        }
        Some(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
    }

    pub(crate) fn dependency_findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (logical_id, resource) in self.resources {
            if let Some(properties) = resource.get("Properties") {
                for dependency in references(properties, self.resources) {
                    findings.push(Finding::relation(
                        dependency,
                        logical_id,
                        EdgeKind::Dependency,
                        "reference",
                        format!(
                            "{logical_id}.Properties contains Ref/GetAtt/Sub; data flow is unverified"
                        ),
                    ));
                }
            }
            let depends_on = match resource.get("DependsOn") {
                Some(Value::String(one)) => vec![one.as_str()],
                Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            for dependency in depends_on {
                findings.push(Finding::relation(
                    dependency,
                    logical_id,
                    EdgeKind::Dependency,
                    "DependsOn",
                    "Provisioning order only",
                ));
            }
        }
        findings
    }
}

/// Logical IDs referenced through Ref, Fn::GetAtt or Fn::Sub, in first-seen order.
fn references<'v>(value: &'v Value, known: &Map<String, Value>) -> Vec<&'v str> {
    let mut found: Vec<&str> = Vec::new();
    let mut add = |name: &'v str| {
        if known.contains_key(name) && !found.contains(&name) {
            found.push(name);
        }
    };
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(map) => {
                if let Some(Value::String(name)) = map.get("Ref") {
                    add(name);
                }
                match map.get("Fn::GetAtt") {
                    Some(Value::Array(parts)) => {
                        if let Some(Value::String(name)) = parts.first() {
                            add(name);
                        }
                    }
                    Some(Value::String(path)) => add(path.split('.').next().unwrap_or(path)),
                    _ => {}
                }
                let (source, overrides) = match map.get("Fn::Sub") {
                    Some(Value::String(source)) => (Some(source.as_str()), None),
                    Some(Value::Array(parts)) => (
                        parts.first().and_then(Value::as_str),
                        parts.get(1).and_then(Value::as_object),
                    ),
                    _ => (None, None),
                };
                if let Some(source) = source {
                    for name in sub_variables(source) {
                        if !overrides.is_some_and(|o| o.contains_key(name)) {
                            add(name);
                        }
                    }
                }
                pending.extend(map.values().rev());
            }
            Value::Array(items) => pending.extend(items.iter().rev()),
            _ => {}
        }
    }
    found
}

const CANONICAL_DEPTH: usize = 64;

fn write_canonical(value: &Value, parent: &str, depth: usize, out: &mut String) {
    if depth > CANONICAL_DEPTH {
        out.push_str("\"…\"");
        return;
    }
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                let child = &map[key];
                if parent == "Environment" && key == "Variables" {
                    write_names(child, out);
                } else {
                    write_canonical(child, key, depth + 1, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) if parent == "Environment" => {
            let names: Vec<&Value> = items.iter().filter_map(|item| item.get("Name")).collect();
            write_canonical(
                &Value::Array(names.into_iter().cloned().collect()),
                "",
                depth + 1,
                out,
            );
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, parent, depth + 1, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

fn write_names(variables: &Value, out: &mut String) {
    let mut names: Vec<&String> = variables
        .as_object()
        .map(|m| m.keys().collect())
        .unwrap_or_default();
    names.sort_unstable();
    out.push_str(&Value::from(names.into_iter().cloned().collect::<Vec<_>>()).to_string());
}

fn sub_variables(source: &str) -> impl Iterator<Item = &str> {
    source.split("${").skip(1).filter_map(|rest| {
        let (variable, _) = rest.split_once('}')?;
        if variable.is_empty() || variable.starts_with('!') {
            return None;
        }
        Some(variable.split('.').next().unwrap_or(variable))
    })
}

pub(crate) struct Resolver<'a> {
    pub pseudo: HashMap<&'static str, String>,
    pub parameters: &'a HashMap<String, String>,
    pub physical: HashMap<&'a str, &'a str>,
}

impl Resolver<'_> {
    pub(crate) fn literal(&self, value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Object(map) => {
                if let Some(Value::String(name)) = map.get("Ref") {
                    return self.reference(name);
                }
                let (logical_id, attribute) = match map.get("Fn::GetAtt")? {
                    Value::Array(parts) => (parts.first()?.as_str()?, parts.get(1)?.as_str()?),
                    Value::String(path) => path.split_once('.')?,
                    _ => return None,
                };
                // Arn and Name identify the same deployed resource as its physical ID.
                matches!(attribute, "Arn" | "Name")
                    .then(|| self.physical.get(logical_id).map(|id| (*id).to_owned()))
                    .flatten()
            }
            _ => None,
        }
    }

    fn reference(&self, name: &str) -> Option<String> {
        self.pseudo
            .get(name)
            .cloned()
            .or_else(|| self.parameters.get(name).cloned())
            .or_else(|| self.physical.get(name).map(|id| (*id).to_owned()))
            .filter(|value| !value.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn finds_ref_getatt_and_sub_references_but_not_overrides() {
        let template = json!({"Resources": {
            "Queue": {"Type": "AWS::SQS::Queue"},
            "Worker": {"Type": "AWS::Lambda::Function"},
            "Table": {"Type": "AWS::DynamoDB::Table"},
            "Other": {"Type": "AWS::Lambda::Function", "DependsOn": "Table", "Properties": {
                "Name": {"Fn::Sub": ["${Queue} ${Worker.Arn} ${!Table}", {"Queue": "literal"}]},
                "Env": {"Variables": {"T": {"Fn::GetAtt": "Table.Arn"}, "U": {"Ref": "AWS::Region"}}}
            }}
        }});
        let view = TemplateView::new(&template).unwrap();
        let edges: Vec<_> = view
            .dependency_findings()
            .into_iter()
            .filter_map(|f| match f {
                Finding::Relation {
                    from, to, label, ..
                } => Some((from, to, label)),
                _ => None,
            })
            .collect();
        assert!(edges.contains(&("Worker".into(), "Other".into(), "reference".into())));
        assert!(edges.contains(&("Table".into(), "Other".into(), "reference".into())));
        assert!(edges.contains(&("Table".into(), "Other".into(), "DependsOn".into())));
        assert!(!edges.iter().any(|(from, _, _)| from == "Queue"));
    }

    #[test]
    fn config_hash_ignores_key_order_and_environment_values() {
        let hash = |properties: Value, physical: &str| {
            let template = json!({"Resources": {"Fn": {"Type": "AWS::Lambda::Function", "Properties": properties}}});
            TemplateView::new(&template)
                .unwrap()
                .config_hash("Fn", physical)
                .unwrap()
        };
        let base = hash(
            json!({"Timeout": 3, "Environment": {"Variables": {"A": "one", "B": "x"}}}),
            "fn",
        );
        assert!(base.starts_with("sha256:"));
        assert_eq!(
            base,
            hash(
                json!({"Environment": {"Variables": {"B": "y", "A": "two"}}, "Timeout": 3}),
                "fn"
            )
        );
        assert_ne!(
            base,
            hash(
                json!({"Timeout": 4, "Environment": {"Variables": {"A": "one", "B": "x"}}}),
                "fn"
            )
        );
        assert_ne!(
            base,
            hash(
                json!({"Timeout": 3, "Environment": {"Variables": {"A": "one"}}}),
                "fn"
            )
        );
        assert_ne!(
            base,
            hash(
                json!({"Timeout": 3, "Environment": {"Variables": {"A": "one", "B": "x"}}}),
                "fn-2"
            )
        );
        let ecs = |value: &str| json!({"ContainerDefinitions": [{"Environment": [{"Name": "TOKEN", "Value": value}]}]});
        assert_eq!(hash(ecs("a"), "t"), hash(ecs("b"), "t"));
    }

    #[test]
    fn resolves_only_pseudo_parameters_parameters_and_physical_ids() {
        let parameters = HashMap::from([("BusName".to_owned(), "external".to_owned())]);
        let resolver = Resolver {
            pseudo: HashMap::from([("AWS::Region", "us-east-1".to_owned())]),
            parameters: &parameters,
            physical: HashMap::from([("Bus", "acct")]),
        };
        assert_eq!(
            resolver.literal(&json!({"Ref": "Bus"})).as_deref(),
            Some("acct")
        );
        assert_eq!(
            resolver
                .literal(&json!({"Fn::GetAtt": ["Bus", "Arn"]}))
                .as_deref(),
            Some("acct")
        );
        assert_eq!(
            resolver.literal(&json!({"Ref": "BusName"})).as_deref(),
            Some("external")
        );
        assert_eq!(
            resolver.literal(&json!({"Ref": "AWS::Region"})).as_deref(),
            Some("us-east-1")
        );
        assert_eq!(resolver.literal(&json!({"Fn::If": ["C", "a", "b"]})), None);
        assert_eq!(resolver.literal(&json!({"Ref": "Missing"})), None);
    }
}
