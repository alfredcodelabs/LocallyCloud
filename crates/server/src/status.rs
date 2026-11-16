pub use locallycloud_core::status::*;

/// The built-in dashboard page, polling `/_locallycloud/status`.
#[cfg(test)]
pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
#[cfg(test)]
pub const DASHBOARD_JS: &str = include_str!("dashboard.js");
#[cfg(test)]
pub const DASHBOARD_I18N: &str = include_str!("dashboard-i18n.js");
#[cfg(test)]
pub const DASHBOARD_CSS: &str = include_str!("dashboard.css");

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dashboard_html_is_embedded() {
        assert!(DASHBOARD_HTML.contains("locallycloud"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/dashboard.js"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/dashboard.css"));
        assert!(!DASHBOARD_HTML.contains("<style>"));
        assert!(DASHBOARD_CSS.contains(".brand-logo"));
        assert!(DASHBOARD_HTML.contains("/_locallycloud/brand/icon.svg"));
        assert!(DASHBOARD_JS.contains("/_locallycloud/status"));
    }
}
