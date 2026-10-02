//! X-Ray trace headers for Lambda invocations.
//!
//! Every invocation carries a `Root=1-<epoch hex>-<24 hex>;Parent=<16 hex>;Sampled=0` header,
//! delivered to the runtime as `Lambda-Runtime-Trace-Id` and exposed as `_X_AMZN_TRACE_ID`.
//! A valid caller-supplied `Root` is preserved so traces correlate across services. Sampling is
//! always off: no X-Ray daemon receives segments, so SDKs must not attempt UDP emission.

use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

/// Build the trace header for one invocation, reusing the `Root` of `incoming` when valid.
pub fn invocation_trace_header(incoming: Option<&str>) -> String {
    let root = incoming
        .and_then(valid_root)
        .map(str::to_owned)
        .unwrap_or_else(new_root);
    format!("Root={root};Parent={};Sampled=0", hex(&random_bytes::<8>()))
}

/// Extract a well-formed `Root=1-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx` value from a header.
fn valid_root(header: &str) -> Option<&str> {
    let root = header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("Root="))?;
    let mut parts = root.split('-');
    let well_formed = parts.next() == Some("1")
        && parts.next().is_some_and(|epoch| is_hex(epoch, 8))
        && parts.next().is_some_and(|id| is_hex(id, 24))
        && parts.next().is_none();
    if well_formed {
        Some(root)
    } else {
        None
    }
}

fn new_root() -> String {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    format!("1-{:08x}-{}", epoch as u32, hex(&random_bytes::<12>()))
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Random bytes drawn from v4 UUIDs, skipping their fixed version and variant bytes.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    let mut filled = 0;
    while filled < N {
        let uuid = Uuid::new_v4();
        let bytes = uuid.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if index == 6 || index == 8 {
                continue;
            }
            if filled == N {
                break;
            }
            out[filled] = *byte;
            filled += 1;
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_format(header: &str) {
        let parts: Vec<&str> = header.split(';').collect();
        assert_eq!(parts.len(), 3, "{header}");
        let root = parts[0].strip_prefix("Root=").unwrap();
        assert_eq!(valid_root(header), Some(root));
        let parent = parts[1].strip_prefix("Parent=").unwrap();
        assert!(is_hex(parent, 16), "{header}");
        assert!(!parent.contains(|c: char| c.is_ascii_uppercase()));
        assert_eq!(parts[2], "Sampled=0");
    }

    #[test]
    fn generated_header_has_xray_format_and_current_epoch() {
        let header = invocation_trace_header(None);
        assert_format(&header);
        let epoch_hex = header.split('-').nth(1).unwrap();
        let epoch = u64::from_str_radix(epoch_hex, 16).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(epoch) < 60);
        assert_ne!(header, invocation_trace_header(None));
    }

    #[test]
    fn valid_incoming_root_is_reused_with_new_parent_and_unsampled() {
        let incoming = "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1";
        let header = invocation_trace_header(Some(incoming));
        assert_format(&header);
        assert!(header.starts_with("Root=1-5759e988-bd862e3fe1be46a994272793;Parent="));
        assert!(!header.contains("53995c3f42cd8ad8"));
        let reordered =
            invocation_trace_header(Some("Sampled=1; Root=1-5759e988-bd862e3fe1be46a994272793"));
        assert!(reordered.starts_with("Root=1-5759e988-bd862e3fe1be46a994272793;"));
    }

    #[test]
    fn malformed_incoming_root_is_replaced() {
        for incoming in [
            "",
            "Root=",
            "Root=2-5759e988-bd862e3fe1be46a994272793",
            "Root=1-5759e98-bd862e3fe1be46a994272793",
            "Root=1-5759e988-bd862e3fe1be46a99427279",
            "Root=1-5759e988-bd862e3fe1be46a994272793-00",
            "Root=1-5759e98g-bd862e3fe1be46a994272793",
            "Root=1-5759e988-bd862e3fe1be46a994272793\r\nX: y",
        ] {
            let header = invocation_trace_header(Some(incoming));
            assert_format(&header);
            assert!(!header.contains("bd862e3fe1be46a99427279"), "{incoming}");
        }
    }
}
