use super::*;

impl Alarms {
    pub(super) fn evaluate(
        &self,
        domain: &MonitoringDomain,
        now: i64,
    ) -> Result<(), MonitoringError> {
        let mut state = self.state.lock().map_err(|_| lock_error())?;
        let records: Vec<_> = state
            .records
            .iter()
            .map(|(key, r)| (key.clone(), r.clone()))
            .collect();
        for ((scope, name), mut record) in records {
            if record.next_eval > now {
                continue;
            }
            let config = &record.config;
            let period = config.period as i64 * 1000;
            let interval = evaluation_interval(config);
            let end = now / interval * interval;
            let key = MetricKey {
                namespace: config.namespace.clone(),
                metric_name: config.metric_name.clone(),
                dimensions: config
                    .dimensions
                    .iter()
                    .map(|d| (d.name.clone(), d.value.clone()))
                    .collect(),
            };
            let points = domain.points(
                &scope,
                &key,
                end - (config.evaluation_periods as i64 + 2) * period,
                end,
                config.unit.as_deref(),
            )?;
            let mut buckets = Vec::new();
            for index in 0..config.evaluation_periods + 2 {
                let upper = end - index as i64 * period;
                let samples: Vec<_> = points
                    .iter()
                    .filter(|p| p.timestamp_ms >= upper - period && p.timestamp_ms < upper)
                    .map(|p| p.value)
                    .collect();
                buckets.push((!samples.is_empty()).then(|| statistic(&config.statistic, &samples)));
            }
            let values: Vec<_> = buckets
                .iter()
                .flatten()
                .copied()
                .take(config.evaluation_periods as usize)
                .collect();
            let real = values.len();
            let breaches = values.iter().filter(|v| breaches(config, **v)).count() as u64;
            let missing = config.evaluation_periods - real as u64;
            let needed = config
                .datapoints_to_alarm
                .unwrap_or(config.evaluation_periods);
            let value = if missing == 0 {
                if breaches >= needed {
                    "ALARM"
                } else {
                    "OK"
                }
            } else {
                match config.treat_missing_data.as_str() {
                    "ignore" => record.state.as_str(),
                    "breaching" => {
                        if breaches + missing >= needed {
                            "ALARM"
                        } else {
                            "OK"
                        }
                    }
                    "notBreaching" => {
                        if breaches >= needed {
                            "ALARM"
                        } else {
                            "OK"
                        }
                    }
                    _ => {
                        let oldest_breach = buckets.iter().rposition(|value| {
                            value.is_some_and(|value| self::breaches(config, value))
                        });
                        let aged_breach = oldest_breach
                            .is_some_and(|index| index as u64 + 1 >= needed)
                            && real > 0
                            && breaches == real as u64;
                        if breaches >= needed || aged_breach {
                            "ALARM"
                        } else if values.iter().any(|value| !self::breaches(config, *value)) {
                            "OK"
                        } else {
                            "INSUFFICIENT_DATA"
                        }
                    }
                }
            }
            .to_owned();
            let reason = format!("Threshold evaluation: {breaches} breaching datapoints, {real} real datapoints, {missing} missing, {needed} required");
            let pending = transition(&scope, &mut record, &value, &reason, now);
            record.next_eval = end + interval;
            self.commit(&mut state, &scope, &name, Some(&record), pending)?;
        }
        Ok(())
    }
}

pub(super) fn evaluation_interval(config: &Config) -> i64 {
    if config.period * config.evaluation_periods > 86400 {
        3_600_000
    } else if config.period < 60 {
        10_000
    } else {
        60_000
    }
}
