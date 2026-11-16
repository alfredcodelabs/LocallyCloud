//! Local orchestration capacity; AWS error contracts and quotas remain in the service.
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudFormationConfig {
    pub operation_capacity: usize,
}
impl Default for CloudFormationConfig {
    fn default() -> Self {
        Self {
            operation_capacity: 4,
        }
    }
}
impl CloudFormationConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=64).contains(&self.operation_capacity) {
            return Err("cloudformation.operation_capacity must be between 1 and 64".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_and_invalid_configuration() {
        let defaults: CloudFormationConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(defaults.operation_capacity, 4);
        for json in [r#"{"operation_capacity":null}"#, r#"{"typo":2}"#] {
            assert!(serde_json::from_str::<CloudFormationConfig>(json).is_err());
        }
        for capacity in [0, 65, usize::MAX] {
            assert!(CloudFormationConfig {
                operation_capacity: capacity
            }
            .validate()
            .is_err());
        }
    }
}
