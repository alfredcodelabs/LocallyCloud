//! Time helpers. Timestamps are ISO-8601 UTC.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current UTC time as an ISO-8601 string.
pub fn now_iso() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

/// Current time as Unix epoch seconds (with fractional millis), as returned by the SFn API.
pub fn now_epoch() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}
