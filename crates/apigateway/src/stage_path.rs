use crate::error::ApiGwError;

pub(crate) fn control_stage_path(path: &str) -> Result<String, ApiGwError> {
    let mut segments: Vec<&str> = path.split('/').collect();
    let index = match segments.as_slice() {
        ["", "v2", "apis", _, "stages", _, ..] => 5,
        ["", "restapis", _, "stages", _, ..] => 4,
        _ => return Ok(path.to_owned()),
    };
    let encoded = segments
        .get(index)
        .ok_or_else(|| ApiGwError::BadRequest("Missing stage name".into()))?;
    if encoded.is_empty() {
        return Ok(path.to_owned());
    }
    let stage = crate::proxy_event::percent_decode(encoded);
    if stage.is_empty()
        || stage.len() > 128
        || (stage != "$default"
            && stage
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_')))
    {
        return Err(ApiGwError::BadRequest("Invalid stage name".into()));
    }
    if let Some(segment) = segments.get_mut(index) {
        *segment = &stage;
    }
    Ok(segments.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_path_decodes_once_without_changing_route_boundaries() {
        assert_eq!(
            control_stage_path("/v2/apis/id/stages/%24default").unwrap(),
            "/v2/apis/id/stages/$default"
        );
        assert_eq!(
            control_stage_path("/restapis/id/stages/%70rod/cache/data").unwrap(),
            "/restapis/id/stages/prod/cache/data"
        );
        assert_eq!(
            control_stage_path("/v2/apis/id/stages/").unwrap(),
            "/v2/apis/id/stages/"
        );
        for name in [
            "%2524default",
            "%24default%2Fcache",
            "%00",
            "%FF",
            "%",
            "a+b",
        ] {
            assert!(
                control_stage_path(&format!("/v2/apis/id/stages/{name}")).is_err(),
                "{name}"
            );
        }
    }
}
