//! IAM ARN construction and path normalization.
//!
//! IAM ARNs are partition-global with an empty region field:
//! `arn:aws:iam::<account>:<resource-type><path><name>`. Paths are always normalized to a
//! single leading and trailing `/`; the root path is `/`.

/// Build an IAM ARN: `arn:aws:iam::<account>:<resource_type><path><name>`.
/// `path` is normalized before embedding (root `/` collapses to `role/name`).
pub fn build_iam_arn(account: &str, resource_type: &str, path: &str, name: &str) -> String {
    format!(
        "arn:aws:iam::{account}:{resource_type}{path}{name}",
        path = normalize_path(path)
    )
}

/// Normalize an IAM path: default `/`, always one leading and one trailing `/`.
pub fn normalize_path(path: &str) -> String {
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("/{trimmed}/")
    }
}

/// Whether `path` falls under `prefix`. An omitted/empty prefix (`/`) matches every path.
pub fn matches_prefix(path: &str, prefix: Option<&str>) -> bool {
    match prefix {
        None => true,
        Some(p) => {
            let p = normalize_path(p);
            if p == "/" {
                true
            } else {
                normalize_path(path).starts_with(&p)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_path_arn() {
        assert_eq!(
            build_iam_arn("000000000000", "role", "/", "my-role"),
            "arn:aws:iam::000000000000:role/my-role"
        );
    }

    #[test]
    fn embedded_path_arn() {
        assert_eq!(
            build_iam_arn("1", "user", "/team/eng", "alice"),
            "arn:aws:iam::1:user/team/eng/alice"
        );
    }

    #[test]
    fn normalize_defaults_and_wraps() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("foo"), "/foo/");
        assert_eq!(normalize_path("/foo"), "/foo/");
        assert_eq!(normalize_path("/foo/bar/"), "/foo/bar/");
    }

    #[test]
    fn prefix_matching() {
        assert!(matches_prefix("/team/eng/", None));
        assert!(matches_prefix("/team/eng/", Some("/")));
        assert!(matches_prefix("/team/eng/", Some("/team")));
        assert!(!matches_prefix("/team/eng/", Some("/ops")));
    }
}
