//! Tag-on-create validation for the native security group resource.
use super::*;

impl Input {
    pub(super) fn security_group_tags(&self) -> Result<BTreeMap<String, String>, Ec2Error> {
        let mut indexes = std::collections::BTreeSet::new();
        for key in self.fields.keys() {
            if [
                "Action",
                "Version",
                "DryRun",
                "VpcId",
                "GroupName",
                "GroupDescription",
                "TagSpecification.1.ResourceType",
            ]
            .contains(&key.as_str())
            {
                continue;
            }
            let Some((index, field)) = key
                .strip_prefix("TagSpecification.1.Tag.")
                .and_then(|suffix| suffix.split_once('.'))
            else {
                return Err(Ec2Error::unsupported(key));
            };
            let number = index
                .parse::<usize>()
                .ok()
                .filter(|number| (1..=50).contains(number) && number.to_string() == index);
            let Some(number) = number else {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Invalid tag list index",
                ));
            };
            if !matches!(field, "Key" | "Value") {
                return Err(Ec2Error::unsupported(key));
            }
            indexes.insert(number);
        }
        let resource_type = self.one("TagSpecification.1.ResourceType")?;
        if resource_type.is_none() && indexes.is_empty() {
            return Ok(BTreeMap::new());
        }
        if resource_type != Some("security-group") {
            return Err(Ec2Error::new(
                "InvalidParameterValue",
                "Tag specification requires security-group resource type",
            ));
        }
        let mut tags = BTreeMap::new();
        for (expected, index) in indexes.into_iter().enumerate() {
            if index != expected + 1 {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Tag indexes must be consecutive",
                ));
            }
            let key = self.required(&format!("TagSpecification.1.Tag.{index}.Key"))?;
            let value = self
                .one(&format!("TagSpecification.1.Tag.{index}.Value"))?
                .unwrap_or("");
            if key.chars().count() > 127
                || key.to_ascii_lowercase().starts_with("aws:")
                || value.chars().count() > 256
                || !xml_text(key)
                || !xml_text(value)
            {
                return Err(Ec2Error::new(
                    "InvalidParameterValue",
                    "Invalid security group tag",
                ));
            }
            if tags.insert(key.into(), value.into()).is_some() {
                return Err(Ec2Error::new("InvalidParameterValue", "Duplicate tag key"));
            }
        }
        Ok(tags)
    }
}

pub(super) fn tags_xml(tags: &BTreeMap<String, String>) -> String {
    let items: String = tags
        .iter()
        .map(|(key, value)| {
            format!(
                "<item><key>{}</key><value>{}</value></item>",
                escape(key),
                escape(value)
            )
        })
        .collect();
    format!("<tagSet>{items}</tagSet>")
}

fn xml_text(value: &str) -> bool {
    value.chars().all(|ch| {
        matches!(ch, '\t' | '\n' | '\r') || (ch >= ' ' && ch != '\u{fffe}' && ch != '\u{ffff}')
    })
}
