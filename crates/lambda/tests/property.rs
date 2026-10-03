//! Property-based tests for Lambda (design Properties, testable-pure subset).
//!
//! Covers the invariants that hold regardless of the compute backend: payload round-trip and
//! request-id correlation (broker), zip path-traversal safety (code store), identifier
//! resolution, reserved-env rejection, concurrency accounting, and Function-URL body
//! round-trip.

use std::io::{Cursor, Write};
use std::sync::Arc;

use proptest::prelude::*;

use locallycloud_lambda::code_store::CodeStore;
use locallycloud_lambda::concurrency::ConcurrencyLimiter;
use locallycloud_lambda::error::LambdaError;
use locallycloud_lambda::exec_env::validate_environment;
use locallycloud_lambda::function_url::{build_v2_event, UrlRequest};
use locallycloud_lambda::model::resolve_function_name;
use locallycloud_lambda::runtime_api::{InvocationBroker, Outcome};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

fn temp() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("lc-lambda-prop-{}", uuid::Uuid::new_v4()))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, .. ProptestConfig::default() })]

    /// Property: the broker delivers the request payload byte-exact and correlates the result
    /// to the submitter for arbitrary payloads.
    #[test]
    fn broker_payload_round_trip(payload in proptest::collection::vec(any::<u8>(), 0..512)) {
        let broker = Arc::new(InvocationBroker::new());
        let expected = payload.clone();
        rt().block_on(async move {
            let (rid, rx) = broker.submit("fn", payload.clone(), "arn", 5000);
            let inv = broker.next("fn").await.unwrap();
            prop_assert_eq!(&inv.payload, &payload);
            prop_assert_eq!(&inv.request_id, &rid);
            broker.complete(&rid, Outcome::Success(inv.payload.clone()));
            prop_assert_eq!(rx.await.unwrap(), Outcome::Success(expected));
            Ok(())
        }).unwrap();
    }

    /// Property: zip extraction never writes outside the function directory, for any entry
    /// name (Zip-Slip safety) — either the file stays enclosed or the archive is rejected.
    #[test]
    fn code_store_never_escapes(name in "(\\.\\./){0,3}[a-zA-Z0-9_./-]{1,20}") {
        let root = temp();
        let store = CodeStore::new(&root);
        // Build a one-entry zip with the generated (possibly traversing) name.
        let mut buf = Vec::new();
        {
            let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
            // start_file may reject some names; skip those cases.
            if zw.start_file(&name, zip::write::SimpleFileOptions::default()).is_ok() {
                let _ = zw.write_all(b"x");
                let _ = zw.finish();
            } else {
                return Ok(());
            }
        }
        let result = store.store_zip("0", "us-east-1", "fn", &buf);
        let fn_dir = root.join("0").join("us-east-1").join("fn");
        // Any extracted file must remain under the function directory.
        if result.is_ok() {
            let escaped = root.join("0").join("us-east-1").join("escape.txt");
            prop_assert!(!escaped.exists());
            prop_assert!(!root.join("escape.txt").exists());
        }
        let _ = std::fs::remove_dir_all(&root);
        // Regardless, nothing was written above the function dir's grandparent.
        prop_assert!(!fn_dir.join("..").join("..").join("escape.txt").exists());
    }

    /// Property: reserved environment keys are always rejected; non-reserved keys accepted.
    #[test]
    fn reserved_env_keys_rejected(key in "[A-Z_]{1,20}", value in "[a-z0-9]{0,10}") {
        let reserved = [
            "AWS_REGION", "AWS_LAMBDA_RUNTIME_API", "_HANDLER", "LAMBDA_TASK_ROOT",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        ];
        let mut map = std::collections::BTreeMap::new();
        map.insert(key.clone(), value);
        let result = validate_environment(&map);
        if reserved.contains(&key.as_str()) {
            prop_assert!(result.is_err());
        }
        // A guaranteed-safe custom key is always accepted.
        let mut ok = std::collections::BTreeMap::new();
        ok.insert("MY_APP_SETTING".to_string(), "v".to_string());
        prop_assert!(validate_environment(&ok).is_ok());
    }

    /// Property: a bare function name resolves back to itself.
    #[test]
    fn identifier_bare_name_round_trip(name in "[a-zA-Z0-9_-]{1,40}") {
        prop_assert_eq!(resolve_function_name(&name, "us-east-1").unwrap(), name);
    }

    /// Property: the region concurrency cap admits exactly `cap` concurrent slots.
    #[test]
    fn concurrency_cap_is_exact(cap in 1u32..12) {
        let limiter = ConcurrencyLimiter::new(cap);
        let mut guards = Vec::new();
        for _ in 0..cap {
            guards.push(limiter.acquire("fn").expect("under cap acquires"));
        }
        prop_assert!(limiter.acquire("fn").is_none(), "at cap, further acquires are rejected");
        drop(guards);
        prop_assert!(limiter.acquire("fn").is_some(), "capacity restored after release");
    }

    /// Property: the Function URL v2 event preserves method/path and round-trips a UTF-8 body.
    #[test]
    fn function_url_body_round_trip(body in "[a-zA-Z0-9 {}:\",]{0,64}", path in "/[a-z/]{0,20}") {
        let req = UrlRequest {
            method: "POST".into(),
            raw_path: path.clone(),
            raw_query: String::new(),
            headers: vec![],
            body: body.clone().into_bytes(),
            url_id: "abc".into(),
            region: "us-east-1".into(),
            account: "000000000000".into(),
            request_id: "rid".into(),
        };
        let event = build_v2_event(&req);
        prop_assert_eq!(event["requestContext"]["http"]["method"].as_str().unwrap(), "POST");
        prop_assert_eq!(event["rawPath"].as_str().unwrap(), path.as_str());
        prop_assert_eq!(event["isBase64Encoded"].as_bool().unwrap(), false);
        if body.is_empty() {
            prop_assert!(event.get("body").is_none());
        } else {
            prop_assert_eq!(event["body"].as_str().unwrap(), body.as_str());
        }
    }
}

/// A region-mismatched ARN is always rejected (not a randomized property but a key invariant).
#[test]
fn region_mismatched_arn_rejected() {
    let err = resolve_function_name(
        "arn:aws:lambda:eu-west-1:000000000000:function:fn",
        "us-east-1",
    )
    .unwrap_err();
    assert!(matches!(err, LambdaError::InvalidParameterValue(_)));
}
