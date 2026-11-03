//! Declarations and dependency references of the processed template.
//!
//! The template is only used for provisioning dependencies, undeployed conditional resources
//! and, where a deployed read cannot name a resource, to pick candidates that a deployed read
//! then verifies. Its property values never leave this module's callers.

use std::collections::HashMap;

use serde_json::{Map, Value};

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

    /// `reference` edges from Ref/GetAtt/Sub in properties, `DependsOn` edges from ordering;
    /// both point from the dependency to its consumer.
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

/// Names of `${Name}` / `${Name.Attr}` variables; `${!Literal}` is an escape.
fn sub_variables(source: &str) -> impl Iterator<Item = &str> {
    source.split("${").skip(1).filter_map(|rest| {
        let (variable, _) = rest.split_once('}')?;
        if variable.is_empty() || variable.starts_with('!') {
            return None;
        }
        Some(variable.split('.').next().unwrap_or(variable))
    })
}

/// Resolves a template value to a string through pseudo parameters, stack parameters and
/// deployed physical IDs only. Conditions and other intrinsics are never evaluated.
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
