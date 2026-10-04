//! CloudFormation template parsing, dependency ordering, and intrinsic-function resolution.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::error::CfnError;
use crate::provision::is_supported_resource_type;

/// A parsed CloudFormation template.
#[derive(Debug, Clone)]
pub struct Template {
    raw: Value,
    declared_transform: Option<String>,
}

/// A resource declaration from the template (properties unresolved).
#[derive(Debug, Clone)]
pub struct ResourceDecl {
    pub logical_id: String,
    pub resource_type: String,
    pub properties: Value,
    pub depends_on: Vec<String>,
    pub condition: Option<String>,
    pub deletion_policy: ResourcePolicy,
    pub update_replace_policy: ResourcePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourcePolicy {
    Delete,
    Retain,
    RetainExceptOnCreate,
}

impl ResourcePolicy {
    fn parse(value: Option<&Value>, logical_id: &str, field: &str) -> Result<Self, CfnError> {
        match value.and_then(Value::as_str) {
            None if value.is_none() => Ok(Self::Delete),
            Some("Delete" | "Snapshot") => Ok(Self::Delete),
            Some("Retain") => Ok(Self::Retain),
            Some("RetainExceptOnCreate") if field == "DeletionPolicy" => {
                Ok(Self::RetainExceptOnCreate)
            }
            _ => Err(CfnError::Validation(format!(
                "Invalid {field} for resource {logical_id}"
            ))),
        }
    }

    pub fn retains_on_delete(self) -> bool {
        matches!(self, Self::Retain | Self::RetainExceptOnCreate)
    }

    pub fn retains_on_rollback(self) -> bool {
        matches!(self, Self::Retain)
    }
}

/// The provisioned facts of a resource, used to resolve `Ref`/`Fn::GetAtt` elsewhere.
#[derive(Debug, Clone, Default)]
pub struct ResolvedResource {
    pub ref_value: String,
    pub attributes: BTreeMap<String, String>,
}

/// Context for intrinsic-function resolution.
pub struct ResolveCtx<'a> {
    pub region: &'a str,
    pub account: &'a str,
    pub stack_name: &'a str,
    pub partition: &'a str,
    pub resources: &'a BTreeMap<String, ResolvedResource>,
    pub parameters: &'a BTreeMap<String, String>,
    pub conditions: &'a BTreeMap<String, bool>,
}

fn validate_resources(raw: &Value) -> Result<(), CfnError> {
    let resources = raw
        .get("Resources")
        .and_then(Value::as_object)
        .ok_or_else(|| CfnError::Validation("Resources must be a JSON object".into()))?;
    for (logical_id, declaration) in resources {
        let declaration = declaration.as_object().ok_or_else(|| {
            CfnError::Validation(format!("Resource {logical_id} must be a JSON object"))
        })?;
        let resource_type = declaration
            .get("Type")
            .and_then(Value::as_str)
            .filter(|resource_type| !resource_type.trim().is_empty())
            .ok_or_else(|| {
                CfnError::Validation(format!(
                    "Resource {logical_id} must have a non-empty string Type"
                ))
            })?;
        if !is_supported_resource_type(resource_type) {
            return Err(CfnError::Validation(format!(
                "Resource {logical_id} has unsupported type {resource_type}"
            )));
        }
        if declaration
            .get("Properties")
            .is_some_and(|properties| !properties.is_object())
        {
            return Err(CfnError::Validation(format!(
                "Properties for resource {logical_id} must be a JSON object"
            )));
        }
        crate::provision::validate_network_property_names(
            logical_id,
            resource_type,
            declaration.get("Properties").unwrap_or(&Value::Null),
        )?;
        if let Some(depends_on) = declaration.get("DependsOn") {
            let valid = match depends_on {
                Value::String(dependency) => !dependency.trim().is_empty(),
                Value::Array(dependencies) => dependencies.iter().all(|dependency| {
                    dependency
                        .as_str()
                        .is_some_and(|dependency| !dependency.trim().is_empty())
                }),
                _ => false,
            };
            if !valid {
                return Err(CfnError::Validation(format!(
                    "DependsOn for resource {logical_id} must be a resource name or an array of resource names"
                )));
            }
        }
        ResourcePolicy::parse(
            declaration.get("DeletionPolicy"),
            logical_id,
            "DeletionPolicy",
        )?;
        ResourcePolicy::parse(
            declaration.get("UpdateReplacePolicy"),
            logical_id,
            "UpdateReplacePolicy",
        )?;
        if declaration
            .get("Condition")
            .is_some_and(|v| v.as_str().is_none_or(str::is_empty))
        {
            return Err(CfnError::Validation(format!(
                "Condition for resource {logical_id} must be a non-empty string"
            )));
        }
    }
    Ok(())
}

impl Template {
    pub fn parse(body: &str) -> Result<Template, CfnError> {
        let mut raw: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(_) => yaml_to_json(
                serde_yaml_ng::from_str(body)
                    .map_err(|e| CfnError::Validation(format!("Template format error: {e}")))?,
            )?,
        };
        if !raw.is_object() {
            return Err(CfnError::Validation(
                "Template must be a JSON object".into(),
            ));
        }
        let declared_transform = raw
            .get("Transform")
            .and_then(Value::as_str)
            .map(str::to_string);
        crate::sam::transform(&mut raw)?;
        validate_resources(&raw)?;
        if let Some(params) = raw.get("Parameters") {
            let definitions = params
                .as_object()
                .ok_or_else(|| CfnError::Validation("Parameters must be an object".into()))?;
            for (name, definition) in definitions {
                let valid = definition
                    .as_object()
                    .is_some_and(|d| d.get("Type").and_then(Value::as_str).is_some());
                if !valid {
                    return Err(CfnError::Validation(format!(
                        "Parameter {name} requires a Type"
                    )));
                }
            }
        }
        let template = Template {
            raw,
            declared_transform,
        };
        template.validate_condition_names()?;
        template.validate_dependency_names()?;
        if template.raw.get("Conditions").is_none() {
            template.ordered_resources()?;
        }
        Ok(template)
    }

    pub fn processed_body(&self) -> Result<String, CfnError> {
        serde_json::to_string(&self.raw).map_err(|_| CfnError::Internal)
    }

    fn validate_dependency_names(&self) -> Result<(), CfnError> {
        let declarations = self.resources();
        let all: BTreeSet<_> = declarations.iter().map(|d| d.logical_id.as_str()).collect();
        let unconditional: BTreeSet<_> = declarations
            .iter()
            .filter(|decl| decl.condition.is_none())
            .map(|decl| decl.logical_id.as_str())
            .collect();
        let mut deps = BTreeMap::new();
        for decl in &declarations {
            for dependency in &decl.depends_on {
                if !all.contains(dependency.as_str()) {
                    return Err(CfnError::Validation(format!(
                        "Resource {} depends on unknown resource {dependency}",
                        decl.logical_id
                    )));
                }
            }
            if decl.condition.is_none() {
                deps.insert(
                    decl.logical_id.as_str(),
                    decl.depends_on
                        .iter()
                        .map(String::as_str)
                        .filter(|name| unconditional.contains(name))
                        .collect::<BTreeSet<_>>(),
                );
            }
        }
        let mut done = BTreeSet::new();
        while done.len() < deps.len() {
            let ready: Vec<_> = deps
                .iter()
                .filter(|(name, refs)| {
                    !done.contains(*name) && refs.iter().all(|name| done.contains(name))
                })
                .map(|(name, _)| *name)
                .collect();
            if ready.is_empty() {
                return Err(CfnError::Validation(
                    "Circular unconditional DependsOn dependency".into(),
                ));
            }
            done.extend(ready);
        }
        Ok(())
    }

    fn validate_condition_names(&self) -> Result<(), CfnError> {
        let definitions =
            match self.raw.get("Conditions") {
                None => None,
                Some(value) => Some(value.as_object().ok_or_else(|| {
                    CfnError::Validation("Conditions must be a JSON object".into())
                })?),
            };
        let exists = |name: &str| definitions.is_some_and(|map| map.contains_key(name));
        for decl in self.resources() {
            if let Some(name) = decl.condition {
                if !exists(&name) {
                    return Err(CfnError::Validation(format!(
                        "Resource {} uses unknown condition {name}",
                        decl.logical_id
                    )));
                }
            }
            validate_if_names(&decl.properties, &exists)?;
        }
        if let Some(outputs) = self.raw.get("Outputs").and_then(Value::as_object) {
            for (name, output) in outputs {
                if let Some(condition) = output.get("Condition").and_then(Value::as_str) {
                    if !exists(condition) {
                        return Err(CfnError::Validation(format!(
                            "Output {name} uses unknown condition {condition}"
                        )));
                    }
                }
                validate_if_names(output, &exists)?;
            }
        }
        if let Some(definitions) = definitions {
            let mut dependencies = BTreeMap::new();
            for (name, expr) in definitions {
                validate_condition_expr(expr, name, &exists)?;
                let mut referenced = BTreeSet::new();
                collect_condition_names(expr, &mut referenced);
                dependencies.insert(name.clone(), referenced);
            }
            let mut done = BTreeSet::new();
            while done.len() < dependencies.len() {
                let ready: Vec<String> = dependencies
                    .iter()
                    .filter(|(name, refs)| {
                        !done.contains(*name) && refs.iter().all(|r| done.contains(r))
                    })
                    .map(|(name, _)| name.clone())
                    .collect();
                if ready.is_empty() {
                    return Err(CfnError::Validation("Circular condition dependency".into()));
                }
                done.extend(ready);
            }
        }
        Ok(())
    }

    pub fn body(&self) -> String {
        self.raw.to_string()
    }

    pub fn declared_transform(&self) -> Option<&str> {
        self.declared_transform.as_deref()
    }

    pub fn description(&self) -> Option<&str> {
        self.raw.get("Description").and_then(Value::as_str)
    }

    pub fn parameter_declarations(&self) -> Vec<(String, Value)> {
        self.raw
            .get("Parameters")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All resource declarations.
    pub fn resources(&self) -> Vec<ResourceDecl> {
        let Some(map) = self.raw.get("Resources").and_then(Value::as_object) else {
            return Vec::new();
        };
        map.iter()
            .map(|(logical_id, decl)| {
                let resource_type = decl
                    .get("Type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let properties = decl
                    .get("Properties")
                    .cloned()
                    .unwrap_or(Value::Object(Default::default()));
                let depends_on = match decl.get("DependsOn") {
                    Some(Value::String(s)) => vec![s.clone()],
                    Some(Value::Array(a)) => a
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect(),
                    _ => Vec::new(),
                };
                ResourceDecl {
                    logical_id: logical_id.clone(),
                    resource_type,
                    properties,
                    depends_on,
                    condition: decl
                        .get("Condition")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    deletion_policy: ResourcePolicy::parse(
                        decl.get("DeletionPolicy"),
                        logical_id,
                        "DeletionPolicy",
                    )
                    .expect("template validated"),
                    update_replace_policy: ResourcePolicy::parse(
                        decl.get("UpdateReplacePolicy"),
                        logical_id,
                        "UpdateReplacePolicy",
                    )
                    .expect("template validated"),
                }
            })
            .collect()
    }

    /// Template outputs as `(name, value_expr, export_name_expr)`.
    pub fn outputs(&self) -> Vec<(String, Value, Option<Value>)> {
        let Some(map) = self.raw.get("Outputs").and_then(Value::as_object) else {
            return Vec::new();
        };
        map.iter()
            .map(|(name, out)| {
                let value = out.get("Value").cloned().unwrap_or(Value::Null);
                let export = out.get("Export").and_then(|e| e.get("Name")).cloned();
                (name.clone(), value, export)
            })
            .collect()
    }

    /// Topologically order resources so dependencies are provisioned first.
    pub fn ordered_resources(&self) -> Result<Vec<ResourceDecl>, CfnError> {
        let decls = self.resources();
        let ids: BTreeSet<String> = decls.iter().map(|d| d.logical_id.clone()).collect();
        let mut deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for decl in &decls {
            let mut set: BTreeSet<String> = decl.depends_on.iter().cloned().collect();
            for dependency in &set {
                if !ids.contains(dependency) {
                    return Err(CfnError::Validation(format!(
                        "Resource {} depends on unknown resource {dependency}",
                        decl.logical_id
                    )));
                }
            }
            for referenced in referenced_ids(&decl.properties) {
                if ids.contains(&referenced) {
                    set.insert(referenced);
                }
            }
            deps.insert(decl.logical_id.clone(), set);
        }

        let mut ordered = Vec::new();
        let mut done: BTreeSet<String> = BTreeSet::new();
        let by_id: BTreeMap<String, ResourceDecl> = decls
            .iter()
            .map(|d| (d.logical_id.clone(), d.clone()))
            .collect();

        while ordered.len() < decls.len() {
            let mut progressed = false;
            for decl in &decls {
                if done.contains(&decl.logical_id) {
                    continue;
                }
                let ready = deps
                    .get(&decl.logical_id)
                    .is_some_and(|dependencies| dependencies.iter().all(|dep| done.contains(dep)));
                if ready {
                    if let Some(resource) = by_id.get(&decl.logical_id) {
                        ordered.push(resource.clone());
                        done.insert(decl.logical_id.clone());
                        progressed = true;
                    }
                }
            }
            if !progressed {
                let cyclic = decls
                    .iter()
                    .filter(|decl| !done.contains(&decl.logical_id))
                    .map(|decl| decl.logical_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(CfnError::Validation(format!(
                    "Circular resource dependency: {cyclic}"
                )));
            }
        }
        Ok(ordered)
    }

    pub fn effective_parameters(
        &self,
        supplied: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let mut parameters: BTreeMap<_, _> = self
            .parameter_declarations()
            .into_iter()
            .filter_map(|(name, definition)| {
                definition.get("Default").map(|value| {
                    let value = value
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| value.to_string());
                    (name, value)
                })
            })
            .collect();
        parameters.extend(supplied.clone());
        parameters
    }

    pub fn evaluate_conditions(
        &self,
        region: &str,
        account: &str,
        supplied: &BTreeMap<String, String>,
    ) -> Result<BTreeMap<String, bool>, CfnError> {
        let definitions = self
            .raw
            .get("Conditions")
            .map(|v| {
                v.as_object()
                    .ok_or_else(|| CfnError::Validation("Conditions must be a JSON object".into()))
            })
            .transpose()?;
        let parameters = self.effective_parameters(supplied);
        let mut evaluated = BTreeMap::new();
        if let Some(definitions) = definitions {
            for name in definitions.keys() {
                eval_condition_named(
                    name,
                    definitions,
                    region,
                    account,
                    &parameters,
                    &mut evaluated,
                    &mut BTreeSet::new(),
                )?;
            }
        }
        for decl in self.resources() {
            if let Some(name) = decl.condition {
                if !evaluated.contains_key(&name) {
                    return Err(CfnError::Validation(format!(
                        "Resource {} uses unknown condition {name}",
                        decl.logical_id
                    )));
                }
            }
        }
        Ok(evaluated)
    }

    pub fn active_resources(
        &self,
        conditions: &BTreeMap<String, bool>,
    ) -> Result<Vec<ResourceDecl>, CfnError> {
        let declarations = self.resources();
        let all: BTreeSet<_> = declarations.iter().map(|d| d.logical_id.clone()).collect();
        let mut candidates = BTreeMap::new();
        let mut dependencies = BTreeMap::new();
        for decl in declarations {
            let mut deps: BTreeSet<String> = decl.depends_on.iter().cloned().collect();
            for dependency in &deps {
                if !all.contains(dependency) {
                    return Err(CfnError::Validation(format!(
                        "Resource {} depends on unknown resource {dependency}",
                        decl.logical_id
                    )));
                }
            }
            deps.extend(
                effective_refs(&decl.properties, conditions)?
                    .into_iter()
                    .filter(|id| all.contains(id)),
            );
            if decl.condition.as_ref().is_none_or(|name| conditions[name]) {
                dependencies.insert(decl.logical_id.clone(), deps);
                candidates.insert(decl.logical_id.clone(), decl);
            }
        }
        loop {
            let omitted: Vec<String> = dependencies
                .iter()
                .filter(|(_, deps)| deps.iter().any(|dep| !candidates.contains_key(dep)))
                .map(|(name, _)| name.clone())
                .collect();
            if omitted.is_empty() {
                break;
            }
            for name in omitted {
                candidates.remove(&name);
                dependencies.remove(&name);
            }
        }

        let mut ordered = Vec::new();
        let mut done = BTreeSet::new();
        while ordered.len() < candidates.len() {
            let next = candidates.keys().find(|name| {
                !done.contains(*name)
                    && dependencies[*name]
                        .iter()
                        .all(|dependency| done.contains(dependency))
            });
            let Some(next) = next else {
                return Err(CfnError::Validation(
                    "Circular resource dependency in active resources".into(),
                ));
            };
            ordered.push(candidates[next].clone());
            done.insert(next.clone());
        }
        Ok(ordered)
    }

    pub fn active_outputs(
        &self,
        conditions: &BTreeMap<String, bool>,
        active: &[ResourceDecl],
    ) -> Result<Vec<(String, Value, Option<Value>)>, CfnError> {
        let all: BTreeSet<_> = self.resources().into_iter().map(|d| d.logical_id).collect();
        let active: BTreeSet<_> = active.iter().map(|d| d.logical_id.as_str()).collect();
        let mut missing = BTreeSet::new();
        let mut result = Vec::new();
        if let Some(outputs) = self.raw.get("Outputs").and_then(Value::as_object) {
            for (name, output) in outputs {
                if let Some(condition) = output.get("Condition").and_then(Value::as_str) {
                    match conditions.get(condition) {
                        Some(false) => continue,
                        Some(true) => {}
                        None => {
                            return Err(CfnError::Validation(format!(
                                "Output {name} uses unknown condition {condition}"
                            )))
                        }
                    }
                }
                for reference in effective_refs(output, conditions)? {
                    if all.contains(&reference) && !active.contains(reference.as_str()) {
                        missing.insert(format!(
                            "Output {name} references omitted resource {reference}"
                        ));
                    }
                }
                result.push((
                    name.clone(),
                    output.get("Value").cloned().unwrap_or(Value::Null),
                    output.get("Export").and_then(|e| e.get("Name")).cloned(),
                ));
            }
        }
        if !missing.is_empty() {
            return Err(CfnError::Validation(
                missing.into_iter().collect::<Vec<_>>().join("; "),
            ));
        }
        Ok(result)
    }
}

fn collect_condition_names(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("Condition") => {
            if let Some(name) = map["Condition"].as_str() {
                out.insert(name.to_string());
            }
        }
        Value::Object(map) => {
            for nested in map.values() {
                collect_condition_names(nested, out);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_condition_names(nested, out);
            }
        }
        _ => {}
    }
}

fn validate_if_names(value: &Value, exists: &impl Fn(&str) -> bool) -> Result<(), CfnError> {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("Fn::If") => {
            let args = map["Fn::If"]
                .as_array()
                .filter(|a| a.len() == 3)
                .ok_or_else(|| {
                    CfnError::Validation("Fn::If requires condition and two branches".into())
                })?;
            let name = args[0]
                .as_str()
                .ok_or_else(|| CfnError::Validation("Fn::If condition must be a string".into()))?;
            if !exists(name) {
                return Err(CfnError::Validation(format!("Unknown condition {name}")));
            }
            validate_if_names(&args[1], exists)?;
            validate_if_names(&args[2], exists)?;
        }
        Value::Object(map) => {
            for child in map.values() {
                validate_if_names(child, exists)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                validate_if_names(child, exists)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_condition_expr(
    expr: &Value,
    owner: &str,
    exists: &impl Fn(&str) -> bool,
) -> Result<(), CfnError> {
    let map = expr
        .as_object()
        .filter(|m| m.len() == 1)
        .ok_or_else(|| CfnError::Validation(format!("Invalid condition expression {owner}")))?;
    let (op, value) = map.iter().next().unwrap();
    match op.as_str() {
        "Condition" => {
            let name = value.as_str().ok_or_else(|| {
                CfnError::Validation("Condition reference must be a string".into())
            })?;
            if !exists(name) {
                return Err(CfnError::Validation(format!("Unknown condition {name}")));
            }
        }
        "Fn::Equals" => {
            if value.as_array().is_none_or(|a| a.len() != 2) {
                return Err(CfnError::Validation(
                    "Fn::Equals requires two operands".into(),
                ));
            }
        }
        "Fn::Not" => {
            let args = value
                .as_array()
                .filter(|a| a.len() == 1)
                .ok_or_else(|| CfnError::Validation("Fn::Not requires one operand".into()))?;
            validate_condition_expr(&args[0], owner, exists)?;
        }
        "Fn::And" | "Fn::Or" => {
            let args = value
                .as_array()
                .filter(|a| (2..=10).contains(&a.len()))
                .ok_or_else(|| CfnError::Validation(format!("{op} requires 2 to 10 operands")))?;
            for arg in args {
                validate_condition_expr(arg, owner, exists)?;
            }
        }
        _ => {
            return Err(CfnError::Validation(format!(
                "Unsupported condition function {op}"
            )))
        }
    }
    Ok(())
}

fn eval_condition_named(
    name: &str,
    definitions: &serde_json::Map<String, Value>,
    region: &str,
    account: &str,
    parameters: &BTreeMap<String, String>,
    evaluated: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> Result<bool, CfnError> {
    if let Some(value) = evaluated.get(name) {
        return Ok(*value);
    }
    let expr = definitions
        .get(name)
        .ok_or_else(|| CfnError::Validation(format!("Unknown condition {name}")))?;
    if !visiting.insert(name.to_string()) {
        return Err(CfnError::Validation(format!("Circular condition {name}")));
    }
    let value = eval_condition_expr(
        expr,
        definitions,
        region,
        account,
        parameters,
        evaluated,
        visiting,
    )?;
    visiting.remove(name);
    evaluated.insert(name.to_string(), value);
    Ok(value)
}

fn eval_condition_expr(
    expr: &Value,
    definitions: &serde_json::Map<String, Value>,
    region: &str,
    account: &str,
    parameters: &BTreeMap<String, String>,
    evaluated: &mut BTreeMap<String, bool>,
    visiting: &mut BTreeSet<String>,
) -> Result<bool, CfnError> {
    let map = expr
        .as_object()
        .filter(|m| m.len() == 1)
        .ok_or_else(|| CfnError::Validation("Invalid condition expression".into()))?;
    let (op, value) = map.iter().next().unwrap();
    match op.as_str() {
        "Condition" => {
            let name = value.as_str().ok_or_else(|| {
                CfnError::Validation("Condition reference must be a string".into())
            })?;
            eval_condition_named(
                name,
                definitions,
                region,
                account,
                parameters,
                evaluated,
                visiting,
            )
        }
        "Fn::Equals" => {
            let args = value
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or_else(|| CfnError::Validation("Fn::Equals requires two operands".into()))?;
            Ok(condition_scalar(&args[0], region, account, parameters)?
                == condition_scalar(&args[1], region, account, parameters)?)
        }
        "Fn::Not" => {
            let args = value
                .as_array()
                .filter(|a| a.len() == 1)
                .ok_or_else(|| CfnError::Validation("Fn::Not requires one operand".into()))?;
            Ok(!eval_condition_expr(
                &args[0],
                definitions,
                region,
                account,
                parameters,
                evaluated,
                visiting,
            )?)
        }
        "Fn::And" | "Fn::Or" => {
            let args = value
                .as_array()
                .filter(|a| (2..=10).contains(&a.len()))
                .ok_or_else(|| CfnError::Validation(format!("{op} requires 2 to 10 operands")))?;
            let values = args
                .iter()
                .map(|arg| {
                    eval_condition_expr(
                        arg,
                        definitions,
                        region,
                        account,
                        parameters,
                        evaluated,
                        visiting,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if op == "Fn::And" {
                values.into_iter().all(|v| v)
            } else {
                values.into_iter().any(|v| v)
            })
        }
        _ => Err(CfnError::Validation(format!(
            "Unsupported condition function {op}"
        ))),
    }
}

fn condition_scalar(
    value: &Value,
    region: &str,
    account: &str,
    parameters: &BTreeMap<String, String>,
) -> Result<String, CfnError> {
    if let Some(name) = value.get("Ref").and_then(Value::as_str) {
        return match name {
            "AWS::Region" => Ok(region.to_string()),
            "AWS::AccountId" => Ok(account.to_string()),
            "AWS::Partition" => Ok("aws".into()),
            _ => parameters.get(name).cloned().ok_or_else(|| {
                CfnError::Validation(format!("Condition references unavailable parameter {name}"))
            }),
        };
    }
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        _ => Err(CfnError::Validation("Invalid condition operand".into())),
    }
}

fn effective_refs(
    value: &Value,
    conditions: &BTreeMap<String, bool>,
) -> Result<Vec<String>, CfnError> {
    let mut refs = Vec::new();
    collect_effective_refs(value, conditions, &mut refs)?;
    Ok(refs)
}

fn collect_effective_refs(
    value: &Value,
    conditions: &BTreeMap<String, bool>,
    out: &mut Vec<String>,
) -> Result<(), CfnError> {
    match value {
        Value::Object(map) if map.len() == 1 => {
            if let Some(conditional) = map.get("Fn::If") {
                let args = conditional
                    .as_array()
                    .filter(|a| a.len() == 3)
                    .ok_or_else(|| {
                        CfnError::Validation("Fn::If requires condition and two branches".into())
                    })?;
                let name = args[0].as_str().ok_or_else(|| {
                    CfnError::Validation("Fn::If condition must be a string".into())
                })?;
                let active = conditions
                    .get(name)
                    .ok_or_else(|| CfnError::Validation(format!("Unknown condition {name}")))?;
                return collect_effective_refs(&args[if *active { 1 } else { 2 }], conditions, out);
            }
            if let Some(name) = map.get("Ref").and_then(Value::as_str) {
                out.push(name.to_string());
                return Ok(());
            }
            if let Some(att) = map.get("Fn::GetAtt") {
                if let Some(id) = att
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .or_else(|| {
                        att.as_str()
                            .and_then(|s| s.split_once('.').map(|(id, _)| id))
                    })
                {
                    out.push(id.to_string());
                }
                return Ok(());
            }
            if let Some(sub) = map.get("Fn::Sub") {
                let (text, locals) = match sub {
                    Value::String(text) => (text.as_str(), None),
                    Value::Array(args) => (
                        args.first().and_then(Value::as_str).unwrap_or(""),
                        args.get(1).and_then(Value::as_object),
                    ),
                    _ => ("", None),
                };
                for token in text
                    .split("${")
                    .skip(1)
                    .filter_map(|s| s.split_once('}').map(|(name, _)| name))
                {
                    if token.starts_with('!') || locals.is_some_and(|vars| vars.contains_key(token))
                    {
                        continue;
                    }
                    out.push(token.split('.').next().unwrap_or(token).to_string());
                }
                if let Some(locals) = locals {
                    for value in locals.values() {
                        collect_effective_refs(value, conditions, out)?;
                    }
                }
                return Ok(());
            }
            for nested in map.values() {
                collect_effective_refs(nested, conditions, out)?;
            }
        }
        Value::Object(map) => {
            for nested in map.values() {
                collect_effective_refs(nested, conditions, out)?;
            }
        }
        Value::Array(items) => {
            for nested in items {
                collect_effective_refs(nested, conditions, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Collect logical ids referenced via `Ref` or `Fn::GetAtt` anywhere in a value.
pub fn referenced_ids(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_refs(value, &mut out);
    out
}

fn collect_refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(target)) = map.get("Ref") {
                out.push(target.clone());
            }
            if let Some(att) = map.get("Fn::GetAtt") {
                match att {
                    Value::Array(a) => {
                        if let Some(Value::String(id)) = a.first() {
                            out.push(id.clone());
                        }
                    }
                    Value::String(s) => {
                        if let Some((id, _)) = s.split_once('.') {
                            out.push(id.to_string());
                        }
                    }
                    _ => {}
                }
            }
            for v in map.values() {
                collect_refs(v, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                collect_refs(v, out);
            }
        }
        _ => {}
    }
}

/// Outcome of resolving a value. `NoValue` marks a `Ref` to `AWS::NoValue` (or a selected
/// `Fn::If` branch resolving to one): it omits the enclosing object key or array element,
/// while plain `null` values are preserved as-is.
enum Resolved {
    Value(Value),
    NoValue,
}

/// Resolve intrinsic functions in a value against the provisioning context.
pub fn resolve(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    Ok(match resolve_value(value, ctx)? {
        Resolved::Value(value) => value,
        Resolved::NoValue => Value::Null,
    })
}

fn resolve_value(value: &Value, ctx: &ResolveCtx) -> Result<Resolved, CfnError> {
    Ok(match value {
        Value::Object(map) if map.len() == 1 => {
            let (key, value) = map.iter().next().unwrap();
            match key.as_str() {
                "Ref" if value.as_str() == Some("AWS::NoValue") => Resolved::NoValue,
                "Ref" => Resolved::Value(resolve_ref(value.as_str().unwrap_or_default(), ctx)?),
                "Fn::GetAtt" => Resolved::Value(resolve_getatt(value, ctx)?),
                "Fn::Join" => Resolved::Value(resolve_join(value, ctx)?),
                "Fn::Sub" => Resolved::Value(resolve_sub(value, ctx)?),
                "Fn::Select" => Resolved::Value(resolve_select(value, ctx)?),
                "Fn::Split" => Resolved::Value(resolve_split(value, ctx)?),
                "Fn::If" => {
                    let args =
                        value
                            .as_array()
                            .filter(|args| args.len() == 3)
                            .ok_or_else(|| {
                                CfnError::Validation(
                                    "Fn::If requires condition and two branches".into(),
                                )
                            })?;
                    let condition = args[0]
                        .as_str()
                        .and_then(|name| ctx.conditions.get(name))
                        .ok_or_else(|| {
                            CfnError::Validation("Fn::If references an unknown condition".into())
                        })?;
                    resolve_value(&args[if *condition { 1 } else { 2 }], ctx)?
                }
                _ => {
                    let mut result = serde_json::Map::new();
                    if let Resolved::Value(value) = resolve_value(value, ctx)? {
                        result.insert(key.clone(), value);
                    }
                    Resolved::Value(Value::Object(result))
                }
            }
        }
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, value) in map {
                if let Resolved::Value(value) = resolve_value(value, ctx)? {
                    result.insert(key.clone(), value);
                }
            }
            Resolved::Value(Value::Object(result))
        }
        Value::Array(values) => {
            let mut result = Vec::with_capacity(values.len());
            for value in values {
                if let Resolved::Value(value) = resolve_value(value, ctx)? {
                    result.push(value);
                }
            }
            Resolved::Value(Value::Array(result))
        }
        value => Resolved::Value(value.clone()),
    })
}

/// Resolve a value to a string (join arrays/scalars sensibly).
pub fn resolve_to_string(value: &Value, ctx: &ResolveCtx) -> Result<String, CfnError> {
    Ok(value_to_string(&resolve(value, ctx)?))
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Null => String::new(),
        value => value.to_string(),
    }
}

fn resolve_ref(name: &str, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    Ok(match name {
        "AWS::Region" => Value::String(ctx.region.into()),
        "AWS::AccountId" => Value::String(ctx.account.into()),
        "AWS::StackName" => Value::String(ctx.stack_name.into()),
        "AWS::Partition" => Value::String(ctx.partition.into()),
        "AWS::URLSuffix" => Value::String("amazonaws.com".into()),
        "AWS::NoValue" => Value::Null,
        "AWS::NotificationARNs" => Value::Array(vec![]),
        name => Value::String(
            ctx.resources
                .get(name)
                .map(|resource| resource.ref_value.clone())
                .or_else(|| ctx.parameters.get(name).cloned())
                .ok_or_else(|| {
                    CfnError::Validation(format!(
                        "Ref references unavailable resource or parameter {name}"
                    ))
                })?,
        ),
    })
}

fn resolve_getatt(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    let parts = match value {
        Value::Array(parts) if parts.len() == 2 => parts[0].as_str().zip(parts[1].as_str()),
        Value::String(value) => value.split_once('.'),
        _ => None,
    };
    let (id, attribute) = parts
        .ok_or_else(|| CfnError::Validation("Fn::GetAtt requires resource and attribute".into()))?;
    ctx.resources
        .get(id)
        .and_then(|resource| resource.attributes.get(attribute))
        .map(|value| Value::String(value.clone()))
        .ok_or_else(|| {
            CfnError::Validation(format!(
                "Fn::GetAtt attribute {id}.{attribute} is unavailable"
            ))
        })
}

fn resolve_join(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    let args = value
        .as_array()
        .filter(|args| args.len() == 2)
        .ok_or_else(|| CfnError::Validation("Fn::Join requires delimiter and list".into()))?;
    let delimiter = args[0]
        .as_str()
        .ok_or_else(|| CfnError::Validation("Fn::Join delimiter must be a string".into()))?;
    let values = resolve(&args[1], ctx)?;
    let values = values
        .as_array()
        .ok_or_else(|| CfnError::Validation("Fn::Join requires a list".into()))?;
    Ok(Value::String(
        values
            .iter()
            .map(value_to_string)
            .collect::<Vec<_>>()
            .join(delimiter),
    ))
}

fn resolve_split(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    let args = value
        .as_array()
        .filter(|args| args.len() == 2)
        .ok_or_else(|| CfnError::Validation("Fn::Split requires delimiter and string".into()))?;
    let delimiter = args[0]
        .as_str()
        .ok_or_else(|| CfnError::Validation("Fn::Split delimiter must be a string".into()))?;
    Ok(Value::Array(
        resolve_to_string(&args[1], ctx)?
            .split(delimiter)
            .map(|value| Value::String(value.into()))
            .collect(),
    ))
}

fn resolve_select(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    let args = value
        .as_array()
        .filter(|args| args.len() == 2)
        .ok_or_else(|| CfnError::Validation("Fn::Select requires index and list".into()))?;
    let index = resolve_to_string(&args[0], ctx)?
        .parse::<usize>()
        .map_err(|_| CfnError::Validation("Fn::Select index must be nonnegative".into()))?;
    let values = resolve(&args[1], ctx)?;
    values
        .as_array()
        .and_then(|values| values.get(index))
        .cloned()
        .ok_or_else(|| CfnError::Validation("Fn::Select index is outside its list".into()))
}

fn resolve_sub(value: &Value, ctx: &ResolveCtx) -> Result<Value, CfnError> {
    let (template, variables) = match value {
        Value::String(template) => (template.as_str(), BTreeMap::new()),
        Value::Array(args) if args.len() == 2 => {
            let template = args[0]
                .as_str()
                .ok_or_else(|| CfnError::Validation("Fn::Sub requires a string template".into()))?;
            let values = args[1]
                .as_object()
                .ok_or_else(|| CfnError::Validation("Fn::Sub variables must be a map".into()))?;
            let variables = values
                .iter()
                .map(|(name, value)| Ok((name.clone(), resolve_to_string(value, ctx)?)))
                .collect::<Result<BTreeMap<_, _>, CfnError>>()?;
            (template, variables)
        }
        _ => {
            return Err(CfnError::Validation(
                "Fn::Sub requires a template or template/variables pair".into(),
            ))
        }
    };
    Ok(Value::String(substitute(template, &variables, ctx)?))
}

/// Expand `${Name}` / `${Name.Attr}` tokens, preserving Unicode and escaped literals.
fn substitute(
    mut template: &str,
    variables: &BTreeMap<String, String>,
    ctx: &ResolveCtx,
) -> Result<String, CfnError> {
    let mut result = String::with_capacity(template.len());
    while let Some(start) = template.find("${") {
        result.push_str(&template[..start]);
        let tail = &template[start + 2..];
        let end = tail
            .find('}')
            .ok_or_else(|| CfnError::Validation("Fn::Sub has an unterminated variable".into()))?;
        let name = &tail[..end];
        if let Some(literal) = name.strip_prefix('!') {
            result.push_str(&format!("${{{literal}}}"));
        } else {
            result.push_str(&resolve_sub_token(name, variables, ctx)?);
        }
        template = &tail[end + 1..];
    }
    result.push_str(template);
    Ok(result)
}

fn resolve_sub_token(
    name: &str,
    variables: &BTreeMap<String, String>,
    ctx: &ResolveCtx,
) -> Result<String, CfnError> {
    if let Some(value) = variables.get(name) {
        return Ok(value.clone());
    }
    if name.contains('.') {
        return Ok(value_to_string(&resolve_getatt(
            &Value::String(name.into()),
            ctx,
        )?));
    }
    Ok(value_to_string(&resolve_ref(name, ctx)?))
}

fn yaml_to_json(value: serde_yaml_ng::Value) -> Result<Value, CfnError> {
    use serde_yaml_ng::Value as Yaml;
    match value {
        Yaml::Null => Ok(Value::Null),
        Yaml::Bool(value) => Ok(Value::Bool(value)),
        Yaml::Number(value) => serde_json::to_value(value)
            .map_err(|_| CfnError::Validation("Invalid YAML number".into())),
        Yaml::String(value) => Ok(Value::String(value)),
        Yaml::Sequence(values) => values
            .into_iter()
            .map(yaml_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Yaml::Mapping(values) => {
            let mut result = serde_json::Map::new();
            for (key, value) in values {
                let Yaml::String(key) = key else {
                    return Err(CfnError::Validation(
                        "YAML template keys must be strings".into(),
                    ));
                };
                result.insert(key, yaml_to_json(value)?);
            }
            Ok(Value::Object(result))
        }
        Yaml::Tagged(tagged) => {
            let tag = tagged.tag.to_string();
            let name = match tag.trim_start_matches('!') {
                "Ref" => "Ref".to_string(),
                "GetAtt" | "Sub" | "Join" | "If" | "Select" | "Split" => {
                    format!("Fn::{}", tag.trim_start_matches('!'))
                }
                _ => return Err(CfnError::Validation(format!("Unsupported YAML tag {tag}"))),
            };
            let mut result = serde_json::Map::new();
            result.insert(name, yaml_to_json(tagged.value)?);
            Ok(Value::Object(result))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    static EMPTY_CONDITIONS: std::sync::LazyLock<BTreeMap<String, bool>> =
        std::sync::LazyLock::new(BTreeMap::new);

    fn ctx_with(
        res: BTreeMap<String, ResolvedResource>,
    ) -> (BTreeMap<String, ResolvedResource>, BTreeMap<String, String>) {
        (res, BTreeMap::new())
    }

    fn ctx<'a>(
        resources: &'a BTreeMap<String, ResolvedResource>,
        parameters: &'a BTreeMap<String, String>,
    ) -> ResolveCtx<'a> {
        ResolveCtx {
            region: "us-east-1",
            account: "000000000000",
            stack_name: "lc-compat-dev",
            partition: "aws",
            resources,
            parameters,
            conditions: &EMPTY_CONDITIONS,
        }
    }

    #[test]
    fn parses_and_orders_by_dependency() {
        let body = json!({
            "Resources": {
                "Fn": { "Type": "AWS::Lambda::Function", "Properties": { "Role": { "Fn::GetAtt": ["Role", "Arn"] } } },
                "Role": { "Type": "AWS::IAM::Role", "Properties": {} }
            }
        })
        .to_string();
        let t = Template::parse(&body).unwrap();
        let ordered = t.ordered_resources().unwrap();
        assert_eq!(
            ordered[0].logical_id, "Role",
            "dependency provisioned first"
        );
        assert_eq!(ordered[1].logical_id, "Fn");
    }

    #[test]
    fn rejects_malformed_resources_and_dependencies() {
        let invalid = [
            json!({}),
            json!({ "Resources": [] }),
            json!({ "Resources": { "Bad": null } }),
            json!({ "Resources": { "Bad": { "Type": "" } } }),
            json!({ "Resources": { "Bad": { "Type": "AWS::MadeUp::Resource" } } }),
            json!({ "Resources": { "Bad": { "Type": "AWS::S3::Bucket", "Properties": [] } } }),
            json!({ "Resources": { "Bad": { "Type": "AWS::S3::Bucket", "DependsOn": 1 } } }),
            json!({ "Resources": { "Bad": { "Type": "AWS::S3::Bucket", "DependsOn": ["Good", 1] }, "Good": { "Type": "AWS::S3::Bucket" } } }),
            json!({ "Resources": { "Bad": { "Type": "AWS::S3::Bucket", "DependsOn": "Missing" } } }),
            json!({ "Resources": { "A": { "Type": "AWS::S3::Bucket", "DependsOn": "B" }, "B": { "Type": "AWS::S3::Bucket", "DependsOn": "A" } } }),
        ];

        for body in invalid {
            assert!(
                Template::parse(&body.to_string()).is_err(),
                "template should be rejected: {body}"
            );
        }
    }

    #[test]
    fn rejects_implicit_resource_cycle() {
        let body = json!({
            "Resources": {
                "A": { "Type": "AWS::S3::BucketPolicy", "Properties": { "Bucket": { "Ref": "B" } } },
                "B": { "Type": "AWS::S3::BucketPolicy", "Properties": { "Bucket": { "Ref": "A" } } }
            }
        });
        assert!(Template::parse(&body.to_string()).is_err());
    }

    #[test]
    fn unavailable_attributes_fail_nested_resolution_and_respect_selected_branches() {
        let resources = BTreeMap::from([(
            "Api".into(),
            ResolvedResource {
                ref_value: "api-id".into(),
                attributes: BTreeMap::from([(
                    "ApiEndpoint".into(),
                    "https://api.execute-api.us-east-1.amazonaws.com".into(),
                )]),
            },
        )]);
        let parameters = BTreeMap::new();
        let mut context = ctx(&resources, &parameters);
        let conditions = BTreeMap::from([("Enabled".into(), true)]);
        context.conditions = &conditions;
        for value in [
            json!({"Nested":[{"Fn::GetAtt":["Api","Missing"]}]}),
            json!({"Fn::Join":["/",[{"Fn::Sub":"${Api.Missing}"},"orders"]]}),
            json!({"Fn::Sub":["${Endpoint}",{"Endpoint":{"Fn::GetAtt":"Api.Missing"}}]}),
        ] {
            let error = resolve(&value, &context).unwrap_err().to_string();
            assert!(error.contains("Api.Missing"), "{error}");
        }
        assert_eq!(resolve(&json!({"Fn::If":["Enabled",{"Fn::GetAtt":"Api.ApiEndpoint"},{"Fn::GetAtt":"Api.Missing"}]}),&context).unwrap(),json!("https://api.execute-api.us-east-1.amazonaws.com"));
        assert_eq!(
            resolve(
                &json!({"Fn::Sub":["á ${Api.Missing} ${!Api.Missing}",{"Api.Missing":"override"}]}),
                &context
            )
            .unwrap(),
            json!("á override ${Api.Missing}")
        );
        assert_eq!(resolve(&json!({"Drop":{"Fn::If":["Enabled",{"Ref":"AWS::NoValue"},{"Fn::GetAtt":"Api.Missing"}]}}),&context).unwrap(),json!({}));
    }

    #[test]
    fn resolves_ref_getatt_join_sub() {
        let mut res = BTreeMap::new();
        res.insert(
            "Bucket".to_string(),
            ResolvedResource {
                ref_value: "my-bucket".into(),
                attributes: BTreeMap::from([(
                    "Arn".to_string(),
                    "arn:aws:s3:::my-bucket".to_string(),
                )]),
            },
        );
        let (resources, params) = ctx_with(res);
        let c = ctx(&resources, &params);

        assert_eq!(
            resolve_to_string(&json!({ "Ref": "Bucket" }), &c).unwrap(),
            "my-bucket"
        );
        assert_eq!(
            resolve_to_string(&json!({ "Fn::GetAtt": ["Bucket", "Arn"] }), &c).unwrap(),
            "arn:aws:s3:::my-bucket"
        );
        assert_eq!(
            resolve_to_string(&json!({ "Ref": "AWS::Region" }), &c).unwrap(),
            "us-east-1"
        );
        assert_eq!(
            resolve_to_string(
                &json!({ "Fn::Join": ["/", [{ "Ref": "Bucket" }, "key"]] }),
                &c
            )
            .unwrap(),
            "my-bucket/key"
        );
        assert_eq!(
            resolve_to_string(&json!({ "Fn::Sub": "${Bucket}-${AWS::AccountId}" }), &c).unwrap(),
            "my-bucket-000000000000"
        );
    }

    #[test]
    fn conditions_select_resources_by_region_and_cascade_dependencies() {
        let template = Template::parse(&json!({
            "Conditions": {
                "East": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]},
                "NotEast": {"Fn::Not": [{"Condition": "East"}]}
            },
            "Resources": {
                "Regional": {"Type": "AWS::S3::Bucket", "Condition": "East"},
                "Dependent": {"Type": "AWS::S3::BucketPolicy", "Properties": {"Bucket": {"Ref": "Regional"}}},
                "Always": {"Type": "AWS::S3::Bucket"}
            },
            "Outputs": {
                "Chosen": {"Value": {"Fn::If": ["East", {"Ref": "Regional"}, {"Ref": "Always"}]}}
            }
        }).to_string()).unwrap();
        let east = template
            .evaluate_conditions("us-east-1", "000000000000", &BTreeMap::new())
            .unwrap();
        let east_active = template.active_resources(&east).unwrap();
        assert_eq!(east_active.len(), 3);
        assert!(template.active_outputs(&east, &east_active).is_ok());
        let west = template
            .evaluate_conditions("us-east-2", "000000000000", &BTreeMap::new())
            .unwrap();
        let west_active = template.active_resources(&west).unwrap();
        assert_eq!(
            west_active
                .iter()
                .map(|r| r.logical_id.as_str())
                .collect::<Vec<_>>(),
            ["Always"]
        );
        assert!(template.active_outputs(&west, &west_active).is_ok());
    }

    #[test]
    fn inactive_if_branch_does_not_create_false_dependency_cycle() {
        let template = Template::parse(
            &json!({
                "Conditions": {"East": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
                "Resources": {
                    "A": {"Type": "AWS::S3::Bucket", "Properties": {
                        "BucketName": {"Fn::If": ["East", "a", {"Ref": "B"}]}
                    }},
                    "B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": {"Ref": "A"}}}
                }
            })
            .to_string(),
        )
        .unwrap();
        let conditions = template
            .evaluate_conditions("us-east-1", "000000000000", &BTreeMap::new())
            .unwrap();
        let ordered = template.active_resources(&conditions).unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|r| r.logical_id.as_str())
                .collect::<Vec<_>>(),
            ["A", "B"]
        );
    }

    #[test]
    fn active_outputs_report_all_omitted_references() {
        let template = Template::parse(
            &json!({
                "Conditions": {"East": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
                "Resources": {
                    "A": {"Type": "AWS::S3::Bucket", "Condition": "East"},
                    "B": {"Type": "AWS::S3::Bucket", "Condition": "East"}
                },
                "Outputs": {
                    "One": {"Value": {"Ref": "A"}},
                    "Two": {"Value": {"Fn::GetAtt": ["B", "Arn"]}}
                }
            })
            .to_string(),
        )
        .unwrap();
        let conditions = template
            .evaluate_conditions("us-east-2", "000000000000", &BTreeMap::new())
            .unwrap();
        let active = template.active_resources(&conditions).unwrap();
        let error = template
            .active_outputs(&conditions, &active)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Output One references omitted resource A"),
            "{error}"
        );
        assert!(
            error.contains("Output Two references omitted resource B"),
            "{error}"
        );
    }

    #[test]
    fn validate_template_rejects_unconditional_depends_on_cycle_with_conditions_present() {
        let bad = json!({
            "Conditions": {"East": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
            "Resources": {
                "A": {"Type": "AWS::S3::Bucket", "DependsOn": "B"},
                "B": {"Type": "AWS::S3::Bucket", "DependsOn": "A"},
                "C": {"Type": "AWS::S3::Bucket", "Condition": "East"}
            }
        });
        assert!(Template::parse(&bad.to_string())
            .unwrap_err()
            .to_string()
            .contains("Circular unconditional DependsOn"));
    }

    #[test]
    fn no_value_removes_array_item_after_if_resolution() {
        let resources = BTreeMap::new();
        let parameters = BTreeMap::new();
        let conditions = BTreeMap::from([("Disabled".to_string(), false)]);
        let ctx = ResolveCtx {
            region: "us-east-1",
            account: "000000000000",
            stack_name: "test",
            partition: "aws",
            resources: &resources,
            parameters: &parameters,
            conditions: &conditions,
        };
        let value = json!([
            "first",
            {"Fn::If": ["Disabled", "second", {"Ref": "AWS::NoValue"}]},
            "third"
        ]);
        assert_eq!(resolve(&value, &ctx).unwrap(), json!(["first", "third"]));
    }

    #[test]
    fn validate_template_rejects_unknown_condition_without_region_parameters() {
        let bad = json!({
            "Conditions": {"Known": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
            "Resources": {"A": {"Type": "AWS::S3::Bucket", "Condition": "Missing"}}
        });
        assert!(Template::parse(&bad.to_string())
            .unwrap_err()
            .to_string()
            .contains("unknown condition Missing"));
    }

    #[test]
    fn ref_no_value_drops_key() {
        let resources = BTreeMap::new();
        let params = BTreeMap::new();
        let c = ctx(&resources, &params);
        let resolved = resolve(
            &json!({ "Keep": "yes", "Drop": { "Ref": "AWS::NoValue" } }),
            &c,
        )
        .unwrap();
        assert_eq!(resolved.get("Keep").unwrap(), "yes");
        assert!(resolved.get("Drop").is_none(), "AWS::NoValue drops the key");
    }

    #[test]
    fn resolve_preserves_literal_nulls_in_objects_and_arrays() {
        let resources = BTreeMap::new();
        let params = BTreeMap::new();
        let c = ctx(&resources, &params);
        let value = json!({
            "NullKey": null,
            "Keep": "yes",
            "List": ["a", null, "b"],
            "Nested": { "Inner": null }
        });
        assert_eq!(resolve(&value, &c).unwrap(), value);
    }

    #[test]
    fn resolve_no_value_nested_in_object_drops_only_that_key() {
        let resources = BTreeMap::new();
        let params = BTreeMap::new();
        let c = ctx(&resources, &params);
        let resolved = resolve(
            &json!({ "Outer": { "Drop": { "Ref": "AWS::NoValue" }, "Keep": 1 } }),
            &c,
        )
        .unwrap();
        assert_eq!(resolved, json!({ "Outer": { "Keep": 1 } }));
    }

    #[test]
    fn no_value_if_branch_omits_key_or_array_item_by_condition() {
        let resources = BTreeMap::new();
        let params = BTreeMap::new();
        let conditions = BTreeMap::from([("Enabled".to_string(), true)]);
        let c = ResolveCtx {
            region: "us-east-1",
            account: "000000000000",
            stack_name: "lc-compat-dev",
            partition: "aws",
            resources: &resources,
            parameters: &params,
            conditions: &conditions,
        };
        let value = json!({
            "Off": { "Fn::If": ["Enabled", { "Ref": "AWS::NoValue" }, "keep"] },
            "On": { "Fn::If": ["Enabled", "keep", { "Ref": "AWS::NoValue" }] },
            "List": [1, { "Fn::If": ["Enabled", { "Ref": "AWS::NoValue" }, 2]}, 3]
        });
        // Enabled=true selects the NoValue branch in "Off" and the list item: both omit.
        let resolved = resolve(&value, &c).unwrap();
        assert_eq!(resolved, json!({ "On": "keep", "List": [1, 3] }));

        let conditions = BTreeMap::from([("Enabled".to_string(), false)]);
        let c = ResolveCtx {
            conditions: &conditions,
            ..c
        };
        // Enabled=false selects "keep" for "Off"; the NoValue branch of "On" is now selected
        // and omits that key.
        let resolved = resolve(&value, &c).unwrap();
        assert_eq!(resolved, json!({ "Off": "keep", "List": [1, 2, 3] }));
    }

    #[test]
    fn resource_policies_parse_and_reject_invalid_values() {
        let template = Template::parse(
            &json!({
                "Resources": {
                    "A": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "RetainExceptOnCreate", "UpdateReplacePolicy": "Retain"}
                }
            })
            .to_string(),
        )
        .expect("valid policies");
        let decl = &template.resources()[0];
        assert_eq!(decl.deletion_policy, ResourcePolicy::RetainExceptOnCreate);
        assert!(decl.deletion_policy.retains_on_delete());
        assert!(!decl.deletion_policy.retains_on_rollback());
        assert_eq!(decl.update_replace_policy, ResourcePolicy::Retain);

        let bad_replace = json!({
            "Resources": {"A": {"Type": "AWS::S3::Bucket", "UpdateReplacePolicy": "RetainExceptOnCreate"}}
        });
        assert!(Template::parse(&bad_replace.to_string())
            .unwrap_err()
            .to_string()
            .contains("Invalid UpdateReplacePolicy"));

        let bad_delete = json!({
            "Resources": {"A": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Bogus"}}
        });
        assert!(Template::parse(&bad_delete.to_string())
            .unwrap_err()
            .to_string()
            .contains("Invalid DeletionPolicy"));
    }
}
