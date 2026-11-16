//! Operational capacities; AWS protocol limits remain fixed.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiGatewayConfig {
    pub http_local_origins: Vec<String>,
    pub websocket_outbound_channel_capacity: usize,
    pub websocket_outbound_history_capacity: usize,
    pub authorizer_cache_capacity: usize,
}

impl Default for ApiGatewayConfig {
    fn default() -> Self {
        Self {
            http_local_origins: Vec::new(),
            websocket_outbound_channel_capacity: 32,
            websocket_outbound_history_capacity: 64,
            authorizer_cache_capacity: 1024,
        }
    }
}

impl ApiGatewayConfig {
    pub fn validate(&self) -> Result<(), String> {
        crate::http_integration::validate_local_origins(&self.http_local_origins)?;
        for (name, value, maximum) in [
            (
                "websocket_outbound_channel_capacity",
                self.websocket_outbound_channel_capacity,
                256,
            ),
            (
                "websocket_outbound_history_capacity",
                self.websocket_outbound_history_capacity,
                1024,
            ),
            (
                "authorizer_cache_capacity",
                self.authorizer_cache_capacity,
                65536,
            ),
        ] {
            if !(1..=maximum).contains(&value) {
                return Err(format!("apigateway.{name} must be between 1 and {maximum}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_capacities_and_unknown_settings() {
        for field in [
            "websocket_outbound_channel_capacity",
            "websocket_outbound_history_capacity",
            "authorizer_cache_capacity",
        ] {
            for value in [0, usize::MAX] {
                let config: ApiGatewayConfig =
                    serde_json::from_value(serde_json::json!({ field: value })).unwrap();
                assert!(config.validate().is_err(), "{field}={value}");
            }
        }
        assert!(
            serde_json::from_str::<ApiGatewayConfig>(r#"{"allow_private_http":true}"#).is_err()
        );
        assert!(
            serde_json::from_str::<ApiGatewayConfig>(r#"{"authorizer_cache_capacity":1.5}"#)
                .is_err()
        );
        let partial: ApiGatewayConfig =
            serde_json::from_str(r#"{"authorizer_cache_capacity":1}"#).unwrap();
        assert!(partial.validate().is_ok());
        assert_eq!(partial.websocket_outbound_channel_capacity, 32);
    }
}
