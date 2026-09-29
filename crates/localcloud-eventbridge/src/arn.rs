use std::fmt;

use crate::error::EventsError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EbArn {
    EventBus {
        region: String,
        account: String,
        name: String,
    },
    Rule {
        region: String,
        account: String,
        bus: String,
        name: String,
    },
    Archive {
        region: String,
        account: String,
        name: String,
    },
    Connection {
        region: String,
        account: String,
        name: String,
    },
    ApiDestination {
        region: String,
        account: String,
        name: String,
    },
    Schedule {
        region: String,
        account: String,
        group: String,
        name: String,
    },
    ScheduleGroup {
        region: String,
        account: String,
        name: String,
    },
    Pipe {
        region: String,
        account: String,
        name: String,
    },
}

impl EbArn {
    pub fn region(&self) -> &str {
        match self {
            Self::EventBus { region, .. }
            | Self::Rule { region, .. }
            | Self::Archive { region, .. }
            | Self::Connection { region, .. }
            | Self::ApiDestination { region, .. }
            | Self::Schedule { region, .. }
            | Self::ScheduleGroup { region, .. }
            | Self::Pipe { region, .. } => region,
        }
    }

    pub fn account(&self) -> &str {
        match self {
            Self::EventBus { account, .. }
            | Self::Rule { account, .. }
            | Self::Archive { account, .. }
            | Self::Connection { account, .. }
            | Self::ApiDestination { account, .. }
            | Self::Schedule { account, .. }
            | Self::ScheduleGroup { account, .. }
            | Self::Pipe { account, .. } => account,
        }
    }

    pub fn parse(value: &str) -> Result<Self, EventsError> {
        let mut parts = value.splitn(6, ':');
        if parts.next() != Some("arn") || parts.next() != Some("aws") {
            return Err(EventsError::Validation("invalid ARN".into()));
        }
        let service = parts.next().unwrap_or_default();
        let region = parts.next().unwrap_or_default().to_string();
        let account = parts.next().unwrap_or_default().to_string();
        let resource = parts.next().unwrap_or_default();
        if region.is_empty() || account.is_empty() || resource.is_empty() {
            return Err(EventsError::Validation("invalid ARN".into()));
        }
        let segments: Vec<&str> = resource.split('/').collect();
        let invalid = || EventsError::Validation("invalid EventBridge ARN".into());
        match (service, segments.as_slice()) {
            ("events", ["event-bus", names @ ..]) if !names.is_empty() => Ok(Self::EventBus {
                region,
                account,
                name: names.join("/"),
            }),
            ("events", ["rule", name]) => Ok(Self::Rule {
                region,
                account,
                bus: "default".into(),
                name: (*name).into(),
            }),
            ("events", ["rule", bus @ .., name]) if !bus.is_empty() => Ok(Self::Rule {
                region,
                account,
                bus: bus.join("/"),
                name: (*name).into(),
            }),
            ("events", ["archive", name]) => Ok(Self::Archive {
                region,
                account,
                name: (*name).into(),
            }),
            ("events", ["connection", name, _]) | ("events", ["connection", name]) => {
                Ok(Self::Connection {
                    region,
                    account,
                    name: (*name).into(),
                })
            }
            ("events", ["api-destination", name, _]) | ("events", ["api-destination", name]) => {
                Ok(Self::ApiDestination {
                    region,
                    account,
                    name: (*name).into(),
                })
            }
            ("scheduler", ["schedule", group, name]) => Ok(Self::Schedule {
                region,
                account,
                group: (*group).into(),
                name: (*name).into(),
            }),
            ("scheduler", ["schedule-group", name]) => Ok(Self::ScheduleGroup {
                region,
                account,
                name: (*name).into(),
            }),
            ("pipes", ["pipe", name]) => Ok(Self::Pipe {
                region,
                account,
                name: (*name).into(),
            }),
            _ => Err(invalid()),
        }
    }
}
impl fmt::Display for EbArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EventBus {
                region,
                account,
                name,
            } => write!(f, "arn:aws:events:{region}:{account}:event-bus/{name}"),
            Self::Rule {
                region,
                account,
                bus,
                name,
            } if bus == "default" => write!(f, "arn:aws:events:{region}:{account}:rule/{name}"),
            Self::Rule {
                region,
                account,
                bus,
                name,
            } => write!(f, "arn:aws:events:{region}:{account}:rule/{bus}/{name}"),
            Self::Archive {
                region,
                account,
                name,
            } => write!(f, "arn:aws:events:{region}:{account}:archive/{name}"),
            Self::Connection {
                region,
                account,
                name,
            } => write!(f, "arn:aws:events:{region}:{account}:connection/{name}"),
            Self::ApiDestination {
                region,
                account,
                name,
            } => write!(
                f,
                "arn:aws:events:{region}:{account}:api-destination/{name}"
            ),
            Self::Schedule {
                region,
                account,
                group,
                name,
            } => write!(
                f,
                "arn:aws:scheduler:{region}:{account}:schedule/{group}/{name}"
            ),
            Self::ScheduleGroup {
                region,
                account,
                name,
            } => write!(
                f,
                "arn:aws:scheduler:{region}:{account}:schedule-group/{name}"
            ),
            Self::Pipe {
                region,
                account,
                name,
            } => write!(f, "arn:aws:pipes:{region}:{account}:pipe/{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_public_arn_shapes() {
        let arns = [
            "arn:aws:events:eu-west-1:123456789012:event-bus/custom",
            "arn:aws:events:eu-west-1:123456789012:rule/default-rule",
            "arn:aws:events:eu-west-1:123456789012:rule/custom/rule",
            "arn:aws:events:eu-west-1:123456789012:archive/history",
            "arn:aws:scheduler:eu-west-1:123456789012:schedule/group/job",
            "arn:aws:scheduler:eu-west-1:123456789012:schedule-group/group",
            "arn:aws:pipes:eu-west-1:123456789012:pipe/pipe",
        ];
        for arn in arns {
            assert_eq!(EbArn::parse(arn).unwrap().to_string(), arn);
        }
    }
}
