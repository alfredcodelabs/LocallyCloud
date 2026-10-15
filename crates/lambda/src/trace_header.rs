//! X-Ray trace headers for Lambda invocations.
//!
//! Every invocation carries a `Root=1-<epoch hex>-<24 hex>;Parent=<16 hex>;Sampled=<0|1>`
//! header, delivered to the runtime as `Lambda-Runtime-Trace-Id` and exposed as
//! `_X_AMZN_TRACE_ID`. A valid caller-supplied `Root` is preserved so traces correlate across
//! services, and each hop gets a new `Parent`: the id of the `AWS::Lambda::Function` segment
//! that the SDK's facade segment stands for. That segment is the child of the hop's
//! `AWS::Lambda` service segment, which is the child of the caller's `Parent`.
//!
//! Sampling follows `TracingConfig.Mode`: a caller decision (`Sampled=1`/`Sampled=0` next to a
//! valid `Root`) is always honored; without one, `PassThrough` does not sample and `Active`
//! applies Lambda's fixed rule, a reservoir of 1 request per second per function plus 5% of
//! the remaining requests.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

use crate::model::TracingMode;

/// Lambda's non-configurable sampling rate beyond the reservoir.
const FIXED_RATE: f64 = 0.05;

/// The trace context of one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationTrace {
    pub root: String,
    /// The id of this hop's function segment, handed to the runtime as `Parent`.
    pub parent: String,
    pub sampled: bool,
    /// The caller's `Parent`, when it supplied a valid one with a valid `Root`.
    pub caller_parent: Option<String>,
    /// The id of this hop's `AWS::Lambda` service segment: the child of `caller_parent` and
    /// the parent of the function segment (`parent`).
    pub service: String,
}

impl InvocationTrace {
    pub fn header(&self) -> String {
        format!(
            "Root={};Parent={};Sampled={}",
            self.root,
            self.parent,
            u8::from(self.sampled)
        )
    }
}

/// Lambda's sampling rule for `Active` functions without an upstream decision.
pub struct Sampler {
    /// The current second and the functions whose reservoir slot it already used.
    reservoir: Mutex<(u64, HashSet<String>)>,
    /// Uniform draw in `[0, 1)`; injectable so tests are deterministic.
    draw: Box<dyn Fn() -> f64 + Send + Sync>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::with_draw(|| {
            let bytes = random_bytes::<4>();
            f64::from(u32::from_be_bytes(bytes)) / (f64::from(u32::MAX) + 1.0)
        })
    }
}

impl Sampler {
    pub fn with_draw(draw: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        Self {
            reservoir: Mutex::new((0, HashSet::new())),
            draw: Box::new(draw),
        }
    }

    fn sample(&self, function: &str) -> bool {
        self.sample_at(function, unix_seconds())
    }

    fn sample_at(&self, function: &str, second: u64) -> bool {
        let reserved = {
            let mut reservoir = self
                .reservoir
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if reservoir.0 != second {
                // Only functions invoked within the current second are retained.
                *reservoir = (second, HashSet::new());
            }
            reservoir.1.insert(function.to_owned())
        };
        reserved || (self.draw)() < FIXED_RATE
    }
}

/// Build the trace context for one invocation of `function` (its unqualified ARN).
pub fn invocation_trace(
    incoming: Option<&str>,
    mode: TracingMode,
    sampler: &Sampler,
    function: &str,
) -> InvocationTrace {
    let root = incoming.and_then(valid_root);
    let decision = root.and(incoming).and_then(incoming_decision);
    let caller_parent = root.and(incoming).and_then(valid_parent).map(str::to_owned);
    let sampled = match (decision, mode) {
        (Some(decision), _) => decision,
        (None, TracingMode::PassThrough) => false,
        (None, TracingMode::Active) => sampler.sample(function),
    };
    InvocationTrace {
        root: root.map(str::to_owned).unwrap_or_else(new_root),
        parent: hex(&random_bytes::<8>()),
        sampled,
        caller_parent,
        service: hex(&random_bytes::<8>()),
    }
}

/// The `PassThrough` header for one invocation, reusing the `Root` (and the sampling decision)
/// of `incoming` when valid.
pub fn invocation_trace_header(incoming: Option<&str>) -> String {
    invocation_trace(incoming, TracingMode::PassThrough, &Sampler::default(), "").header()
}

fn field<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(name)?.strip_prefix('='))
}

/// Extract a well-formed `Root=1-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx` value from a header.
fn valid_root(header: &str) -> Option<&str> {
    let root = field(header, "Root")?;
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

fn valid_parent(header: &str) -> Option<&str> {
    field(header, "Parent").filter(|parent| is_hex(parent, 16))
}

/// `Sampled=1` or `Sampled=0`; `Sampled=?` and other values defer the decision.
fn incoming_decision(header: &str) -> Option<bool> {
    match field(header, "Sampled")? {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn new_root() -> String {
    format!(
        "1-{:08x}-{}",
        unix_seconds() as u32,
        hex(&random_bytes::<12>())
    )
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

    const ROOT: &str = "Root=1-5759e988-bd862e3fe1be46a994272793";

    fn assert_format(header: &str, sampled: &str) {
        let parts: Vec<&str> = header.split(';').collect();
        assert_eq!(parts.len(), 3, "{header}");
        let root = parts[0].strip_prefix("Root=").unwrap();
        assert_eq!(valid_root(header), Some(root));
        let parent = parts[1].strip_prefix("Parent=").unwrap();
        assert!(is_hex(parent, 16), "{header}");
        assert!(!parent.contains(|c: char| c.is_ascii_uppercase()));
        assert_eq!(parts[2], format!("Sampled={sampled}"), "{header}");
    }

    #[test]
    fn generated_header_has_xray_format_and_current_epoch() {
        let header = invocation_trace_header(None);
        assert_format(&header, "0");
        let epoch_hex = header.split('-').nth(1).unwrap();
        let epoch = u64::from_str_radix(epoch_hex, 16).unwrap();
        assert!(unix_seconds().abs_diff(epoch) < 60);
        assert_ne!(header, invocation_trace_header(None));
    }

    #[test]
    fn valid_incoming_root_is_reused_with_new_parent() {
        let incoming = format!("{ROOT};Parent=53995c3f42cd8ad8;Sampled=1");
        let trace = invocation_trace(
            Some(&incoming),
            TracingMode::PassThrough,
            &Sampler::default(),
            "f",
        );
        assert_format(&trace.header(), "1");
        assert!(trace.header().starts_with(&format!("{ROOT};Parent=")));
        assert_ne!(trace.parent, "53995c3f42cd8ad8");
        assert_eq!(trace.caller_parent.as_deref(), Some("53995c3f42cd8ad8"));
        // The service segment sits between the caller and the function segment.
        assert!(is_hex(&trace.service, 16));
        assert_ne!(trace.service, trace.parent);
        assert!(!trace.header().contains(&trace.service));
        let reordered =
            invocation_trace_header(Some("Sampled=1; Root=1-5759e988-bd862e3fe1be46a994272793"));
        assert!(reordered.starts_with(&format!("{ROOT};")));
    }

    #[test]
    fn malformed_incoming_root_is_replaced_and_its_decision_ignored() {
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
            let header = invocation_trace_header(Some(&format!("{incoming};Sampled=1")));
            assert_format(&header, "0");
            assert!(!header.contains("bd862e3fe1be46a99427279"), "{incoming}");
        }
        let trace = invocation_trace(
            Some(&format!("{ROOT};Parent=XYZ;Sampled=1")),
            TracingMode::PassThrough,
            &Sampler::default(),
            "f",
        );
        assert_eq!(trace.caller_parent, None);
    }

    #[test]
    fn sampling_matrix_by_mode_and_caller_decision() {
        // A draw that never falls under the fixed rate isolates the reservoir.
        let never = || Sampler::with_draw(|| 0.99);
        for (mode, incoming, expected) in [
            (TracingMode::Active, Some("Sampled=1"), true),
            (TracingMode::Active, Some("Sampled=0"), false),
            (TracingMode::Active, Some("Sampled=?"), true),
            (TracingMode::Active, None, true),
            (TracingMode::PassThrough, Some("Sampled=1"), true),
            (TracingMode::PassThrough, Some("Sampled=0"), false),
            (TracingMode::PassThrough, Some("Sampled=?"), false),
            (TracingMode::PassThrough, None, false),
        ] {
            let header = incoming.map(|decision| format!("{ROOT};{decision}"));
            let trace = invocation_trace(header.as_deref(), mode, &never(), "f");
            assert_eq!(trace.sampled, expected, "{mode:?} {incoming:?}");
            assert_format(&trace.header(), if expected { "1" } else { "0" });
        }
        // A decision without a valid Root starts a new trace, so Active samples it itself.
        let sampler = never();
        let trace = invocation_trace(Some("Sampled=0"), TracingMode::Active, &sampler, "f");
        assert!(trace.sampled);
    }

    #[test]
    fn active_reservoir_is_one_per_second_per_function_plus_fixed_rate() {
        let sampler = Sampler::with_draw(|| 0.99);
        assert!(sampler.sample_at("a", 100));
        assert!(!sampler.sample_at("a", 100));
        assert!(sampler.sample_at("b", 100));
        assert!(!sampler.sample_at("b", 100));
        assert!(sampler.sample_at("a", 101));
        assert!(!sampler.sample_at("a", 101));
        assert_eq!(sampler.reservoir.lock().unwrap().1.len(), 1);

        let draws = std::sync::atomic::AtomicUsize::new(0);
        let fixed = Sampler::with_draw(move || {
            // 1 in 20 draws falls under 5%.
            let n = draws.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n.is_multiple_of(20) {
                0.01
            } else {
                0.5
            }
        });
        assert!(fixed.sample_at("a", 7));
        let sampled = (0..100).filter(|_| fixed.sample_at("a", 7)).count();
        assert_eq!(sampled, 5);
        // The default draw stays within [0, 1).
        let default = Sampler::default();
        assert!((0..1000).all(|_| (0.0..1.0).contains(&(default.draw)())));
    }
}
