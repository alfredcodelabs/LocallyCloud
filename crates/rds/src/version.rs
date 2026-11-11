//! Supported PostgreSQL versions and their explicitly installed runtime packs.
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Major {
    V16,
    V17,
    V18,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct EngineVersion {
    major: Major,
    minor: Option<u32>,
}

impl Default for EngineVersion {
    fn default() -> Self {
        Self {
            major: Major::V18,
            minor: None,
        }
    }
}

impl EngineVersion {
    pub fn major(self) -> &'static str {
        match self.major {
            Major::V16 => "16",
            Major::V17 => "17",
            Major::V18 => "18",
        }
    }

    pub fn runtime(self) -> &'static str {
        match self.major {
            Major::V16 => "postgres16",
            Major::V17 => "postgres17",
            Major::V18 => "postgres18",
        }
    }

    pub fn binary(self, tool: &str) -> String {
        format!("/usr/lib/postgresql/{}/bin/{tool}", self.major())
    }

    pub fn matches(self, actual: Self) -> bool {
        self.major == actual.major && self.minor.is_none_or(|minor| Some(minor) == actual.minor)
    }

    pub fn from_server_number(number: &str) -> Result<Self, String> {
        let number: u32 = number
            .trim()
            .parse()
            .map_err(|_| "Invalid PostgreSQL server version")?;
        format!("{}.{}", number / 10000, number % 10000).parse()
    }
}

impl std::fmt::Display for EngineVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.major())?;
        if let Some(minor) = self.minor {
            write!(f, ".{minor}")?;
        }
        Ok(())
    }
}

impl FromStr for EngineVersion {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (major, minor) = match value.split_once('.') {
            Some((major, minor)) => {
                let parsed = minor
                    .parse::<u32>()
                    .ok()
                    .filter(|n| n.to_string() == minor)
                    .ok_or("EngineVersion must be a supported PostgreSQL major or major.minor")?;
                (major, Some(parsed))
            }
            None => (value, None),
        };
        let major = match major {
            "16" => Major::V16,
            "17" => Major::V17,
            "18" => Major::V18,
            _ => return Err("Supported PostgreSQL major versions are 16, 17 and 18".into()),
        };
        Ok(Self { major, minor })
    }
}

impl TryFrom<String> for EngineVersion {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
impl From<EngineVersion> for String {
    fn from(value: EngineVersion) -> Self {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_allowlisted_and_minor_requests_are_exact() {
        for (version, runtime) in [
            ("16.15", "postgres16"),
            ("17.11", "postgres17"),
            ("18.6", "postgres18"),
        ] {
            let version: EngineVersion = version.parse().unwrap();
            assert_eq!(version.runtime(), runtime);
            let json = serde_json::to_string(&version).unwrap();
            assert_eq!(
                serde_json::from_str::<EngineVersion>(&json).unwrap(),
                version
            );
        }
        assert_eq!(EngineVersion::default().runtime(), "postgres18");
        assert_eq!(
            EngineVersion::from_server_number("180006")
                .unwrap()
                .to_string(),
            "18.6"
        );
        assert!("18"
            .parse::<EngineVersion>()
            .unwrap()
            .matches("18.6".parse().unwrap()));
        assert!(!"18.5"
            .parse::<EngineVersion>()
            .unwrap()
            .matches("18.6".parse().unwrap()));
        assert!(!"16"
            .parse::<EngineVersion>()
            .unwrap()
            .matches("18.6".parse().unwrap()));
        for invalid in [
            "",
            "19",
            "18beta1",
            "018",
            "18.",
            "18.06",
            "18.6.1",
            "18/../16",
            "18.-1",
            "18.4294967296",
        ] {
            assert!(invalid.parse::<EngineVersion>().is_err(), "{invalid}");
        }
    }
}
