//! Property-based tests for SNS invariants (design properties: ARN round-trip, envelope
//! fidelity, filter correctness/determinism, digest determinism). Real engine, no mocks.

use std::collections::BTreeMap;

use proptest::prelude::*;
use serde_json::json;

use localcloud_sns::digest::{md5_hex, sha256_hex};
use localcloud_sns::envelope::Notification;
use localcloud_sns::filter;
use localcloud_sns::model::TopicArn;

proptest! {
    // TopicArn round-trips through its string form.
    #[test]
    fn topic_arn_round_trip(
        region in "[a-z]{2}-[a-z]{4,9}-[1-9]",
        account in "[0-9]{12}",
        name in "[A-Za-z0-9_-]{1,64}",
    ) {
        let arn = TopicArn::new(&region, &account, &name);
        let parsed = TopicArn::parse(&arn.to_arn()).expect("valid arn parses");
        prop_assert_eq!(parsed.region, region);
        prop_assert_eq!(parsed.account, account);
        prop_assert_eq!(parsed.name, name);
    }

    // The notification envelope preserves the message verbatim and is always a Notification.
    #[test]
    fn envelope_preserves_message(msg in "[ -~]{0,200}") {
        let attrs = BTreeMap::new();
        let n = Notification {
            message_id: "mid",
            topic_arn: "arn:aws:sns:us-east-1:000000000000:t",
            subscription_arn: "arn:aws:sns:us-east-1:000000000000:t:sub",
            message: &msg,
            subject: None,
            timestamp: "2026-01-01T00:00:00Z",
            attributes: &attrs,
        };
        let env = n.envelope();
        prop_assert_eq!(env["Type"].as_str().unwrap(), "Notification");
        prop_assert_eq!(env["Message"].as_str().unwrap(), msg.as_str());
        prop_assert!(env.get("Subject").is_none());
    }

    // Digests are deterministic and well-formed.
    #[test]
    fn digests_are_deterministic(s in "[ -~]{0,128}") {
        prop_assert_eq!(sha256_hex(&s), sha256_hex(&s));
        prop_assert_eq!(md5_hex(&s), md5_hex(&s));
        let md5 = md5_hex(&s);
        prop_assert_eq!(md5.len(), 32);
        prop_assert!(md5.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Body filter is deterministic and matches an exact attribute value.
    #[test]
    fn body_filter_is_deterministic_and_correct(value in "[a-z]{1,12}") {
        let policy = json!({ "event": [value.clone()] });
        let matching = json!({ "event": value }).to_string();
        let r1 = filter::matches_body(&policy, &matching);
        let r2 = filter::matches_body(&policy, &matching);
        prop_assert_eq!(r1, r2);
        prop_assert!(r1, "policy must match a body carrying the exact value");
        let non_matching = json!({ "event": "definitely-not-it-xyz" }).to_string();
        prop_assert!(!filter::matches_body(&policy, &non_matching));
    }
}

#[test]
fn validate_rejects_non_object_policy() {
    assert!(filter::validate("\"not-an-object\"").is_err());
    assert!(filter::validate("{\"k\":[\"v\"]}").is_ok());
    assert!(filter::validate("{\"k\":\"v\"}").is_err());
    assert!(filter::validate("{\"k\":[{\"unknown\":true}]}").is_err());
    assert!(filter::validate("{\"k\":[{\"numeric\":[\">\",\"not-a-number\"]}]}").is_err());
}
