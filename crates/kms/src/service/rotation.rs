//! Rotation uses the same durable per-key mutation as lifecycle changes. Historical
//! generations remain decrypt-only; maintenance runs lazily when the key is resolved.
use super::*;

const DAY: f64 = 86_400.0;

fn next_date(now: f64, days: u32) -> Result<f64, KmsError> {
    let next = now + f64::from(days) * DAY;
    if !now.is_finite() || now < 0.0 || !next.is_finite() || next <= now {
        return Err(KmsError::Internal);
    }
    Ok(next)
}

fn rotate(key: &mut KeyRecord) -> Result<(), KmsError> {
    let version = key
        .material_version
        .checked_add(1)
        .ok_or(KmsError::LimitExceeded)?;
    let fresh = crypto::generate_material()?;
    let previous = std::mem::replace(&mut key.material, fresh);
    key.historical_materials
        .insert(key.material_version, previous);
    key.material_version = version;
    Ok(())
}

fn compatible(key: &KeyRecord) -> Result<(), KmsError> {
    if key.manager != KeyManager::Customer {
        return Err(KmsError::Unsupported);
    }
    if !key.is_enabled() {
        return Err(inactive_key_error(key));
    }
    Ok(())
}

fn selector(body: &Map<String, Value>) -> Result<&str, KmsError> {
    let value = required_string(body, "KeyId")?;
    if value.starts_with("alias/") || value.contains(":alias/") {
        return Err(KmsError::Validation);
    }
    Ok(value)
}

impl KmsService {
    pub(super) fn rotate_if_due(&self, scope: &Scope, id: &str) -> Result<(), KmsError> {
        let now = (self.clock)()?;
        let needed = self
            .store
            .with_key(scope, id, |key| {
                (key.manager == KeyManager::Aws && !key.rotation.enabled)
                    || (key.is_enabled()
                        && key.rotation.enabled
                        && key.rotation.next_date.is_some_and(|date| date <= now))
            })
            .unwrap_or(false);
        if !needed {
            return Ok(());
        }
        self.store.with_key_mut(scope, id, |key| {
            if key.manager == KeyManager::Aws && !key.rotation.enabled {
                key.rotation.enabled = true;
                key.rotation.period_days = 365;
                key.rotation.next_date = Some(next_date(key.creation_date, 365)?);
            }
            if key.is_enabled()
                && key.rotation.enabled
                && key.rotation.next_date.is_some_and(|date| date <= now)
            {
                // No catch-up loop: unused/disabled keys install one fresh generation
                // when maintenance observes they are due, then resume their schedule.
                let next = next_date(now, key.rotation.period_days)?;
                rotate(key)?;
                key.rotation.next_date = Some(next);
            }
            Ok(())
        })?;
        Ok(())
    }

    pub(super) fn set_key_rotation(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
        enabled: bool,
    ) -> Result<Value, KmsError> {
        require_known_fields(
            body,
            if enabled {
                &["KeyId", "RotationPeriodInDays"]
            } else {
                &["KeyId"]
            },
        )?;
        let period = match body.get("RotationPeriodInDays") {
            None => 365,
            Some(value) => value
                .as_u64()
                .filter(|value| (90..=2560).contains(value))
                .ok_or(KmsError::Validation)? as u32,
        };
        let id = self.resolve_key_id(selector(body)?, scope)?;
        let now = (self.clock)()?;
        self.store
            .with_key_mut(scope, &id, |key| {
                compatible(key)?;
                if enabled && (!key.rotation.enabled || key.rotation.period_days != period) {
                    key.rotation.next_date = Some(next_date(now, period)?);
                }
                key.rotation.enabled = enabled;
                if enabled {
                    key.rotation.period_days = period;
                } else {
                    key.rotation.next_date = None;
                }
                Ok(())
            })?
            .ok_or(KmsError::NotFound)?;
        Ok(Value::Null)
    }

    pub(super) fn get_key_rotation_status(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId"])?;
        let id = self.resolve_key_id(selector(body)?, scope)?;
        self.store
            .with_key(scope, &id, |key| {
                let enabled =
                    key.rotation.enabled && !matches!(key.state, KeyState::PendingDeletion { .. });
                let mut value = json!({"KeyId":scope.key_arn(&id), "KeyRotationEnabled":enabled});
                if enabled {
                    value["RotationPeriodInDays"] = json!(key.rotation.period_days);
                    if let Some(date) = key.rotation.next_date {
                        value["NextRotationDate"] = json!(date);
                    }
                }
                value
            })
            .ok_or(KmsError::NotFound)
    }

    pub(super) fn rotate_on_demand(
        &self,
        body: &Map<String, Value>,
        scope: &Scope,
    ) -> Result<Value, KmsError> {
        require_known_fields(body, &["KeyId"])?;
        let id = self.resolve_key_id(selector(body)?, scope)?;
        let now = (self.clock)()?;
        self.store
            .with_key_mut(scope, &id, |key| {
                compatible(key)?;
                if key.rotation.on_demand_count >= 25 {
                    return Err(KmsError::LimitExceeded);
                }
                if key.rotation.enabled
                    && key
                        .rotation
                        .next_date
                        .is_some_and(|date| date > now && date - now <= 1200.0)
                {
                    return Err(KmsError::Conflict);
                }
                rotate(key)?;
                key.rotation.on_demand_count += 1;
                Ok(())
            })?
            .ok_or(KmsError::NotFound)?;
        Ok(json!({"KeyId":scope.key_arn(&id)}))
    }
}

#[cfg(test)]
mod tests;
