use super::*;
use proptest::prelude::*;

#[derive(Default)]
struct Work {
    visited: usize,
    prefix_comparisons: usize,
}

// Previous traversal/token algorithm, with the two confirmed AWS normalizations:
// work is capped at 1000 results, and max-keys=0 is an empty, nontruncated page.
fn reference_listing<const COUNT: bool>(
    objects: &BTreeMap<String, StoredObject>,
    prefix: &str,
    delimiter: Option<&str>,
    start_after: Option<&str>,
    max_keys: usize,
    work: &mut Work,
) -> ListResult {
    let max_keys = max_keys.min(DEFAULT_MAX_KEYS);
    if max_keys == 0 {
        return ListResult {
            keys: Vec::new(),
            common_prefixes: Vec::new(),
            is_truncated: false,
            next_token: None,
        };
    }
    let mut keys = Vec::new();
    let mut common_prefixes: Vec<String> = Vec::new();
    let mut is_truncated = false;
    let mut next_token = None;
    let mut last_consumed_key = None;
    for (key, obj) in objects {
        if COUNT {
            work.visited += 1;
        }
        if !key.starts_with(prefix) {
            continue;
        }
        if let Some(after) = start_after {
            if key.as_str() <= after {
                continue;
            }
        }
        if let Some(delimiter) = delimiter {
            let rest = &key[prefix.len()..];
            if let Some(index) = rest.find(delimiter) {
                let common_prefix = format!("{prefix}{}", &rest[..index + delimiter.len()]);
                if !common_prefixes.iter().any(|value| {
                    if COUNT {
                        work.prefix_comparisons += 1;
                    }
                    value == &common_prefix
                }) {
                    if keys.len() + common_prefixes.len() >= max_keys {
                        is_truncated = true;
                        next_token = last_consumed_key;
                        break;
                    }
                    common_prefixes.push(common_prefix);
                }
                last_consumed_key = Some(key.clone());
                continue;
            }
        }
        if keys.len() + common_prefixes.len() >= max_keys {
            is_truncated = true;
            next_token = last_consumed_key;
            break;
        }
        keys.push((key.clone(), obj.clone()));
        last_consumed_key = Some(key.clone());
    }
    ListResult {
        keys,
        common_prefixes,
        is_truncated,
        next_token,
    }
}

fn object() -> StoredObject {
    StoredObject {
        body: StoredBody::Inline(Bytes::from_static(b"owned")),
        etag: "\"owned\"".into(),
        checksums: BTreeMap::new(),
        content_type: "application/octet-stream".into(),
        last_modified: OffsetDateTime::UNIX_EPOCH,
        metadata: BTreeMap::new(),
        storage_class: "STANDARD".into(),
        tags: BTreeMap::new(),
        retention: None,
        legal_hold: false,
        encryption: ServerSideEncryption::default(),
        parts: Vec::new(),
    }
}

fn snapshot(result: ListResult) -> serde_json::Value {
    serde_json::json!({
        "keys": result.keys,
        "common_prefixes": result.common_prefixes,
        "is_truncated": result.is_truncated,
        "next_token": result.next_token,
    })
}

#[test]
fn listing_matches_previous_algorithm_at_prefix_marker_and_delimiter_boundaries() {
    let keys = [
        "", "a", "a/", "a/0", "a/1", "a/α", "a/α/0", "a//0", "a/🦀/0", "a0", "ab", "ababa", "b",
        "b/0", "é", "é/0", "é/1", "🦀", "🦀/0", "🦀/1",
    ];
    let objects = keys.into_iter().map(|key| (key.into(), object())).collect();
    for prefix in [
        "", "a", "a/", "a/α", "a/🦀", "a0", "ab", "b/", "missing", "é", "🦀/",
    ] {
        for marker in [
            None,
            Some(""),
            Some("a"),
            Some("a/"),
            Some("a/0"),
            Some("a/α/0"),
            Some("a/🦀"),
            Some("b"),
            Some("z"),
            Some("é/0"),
            Some("🦀/0"),
            Some("🦀/9"),
        ] {
            for delimiter in [
                None,
                Some(""),
                Some("/"),
                Some("//"),
                Some("aba"),
                Some("é"),
                Some("α"),
                Some("🦀"),
            ] {
                for max_keys in [0, 1, 2, 3, 20, 1000, usize::MAX] {
                    let expected = reference_listing::<true>(
                        &objects,
                        prefix,
                        delimiter,
                        marker,
                        max_keys,
                        &mut Work::default(),
                    );
                    let actual = compute_listing(&objects, prefix, delimiter, marker, max_keys);
                    assert_eq!(snapshot(actual), snapshot(expected), "prefix={prefix:?} marker={marker:?} delimiter={delimiter:?} max_keys={max_keys}");
                }
            }
        }
    }
    assert_eq!(
        snapshot(compute_listing(&BTreeMap::new(), "", Some(""), None, 0)),
        snapshot(reference_listing::<true>(
            &BTreeMap::new(),
            "",
            Some(""),
            None,
            0,
            &mut Work::default()
        ))
    );
}

proptest! {
    #[test]
    fn listing_matches_previous_algorithm_for_generated_keys(
        keys in proptest::collection::btree_set("[a-c/éα🦀]{0,10}", 0..64),
        prefix in "[a-c/éα🦀]{0,4}",
        marker in proptest::option::of("[a-c/éα🦀]{0,6}"),
        delimiter in proptest::option::of("[a-c/éα🦀]{0,3}"),
        max_keys in 0usize..20,
    ) {
        let objects = keys.into_iter().map(|key| (key, object())).collect();
        let expected = reference_listing::<true>(&objects, &prefix, delimiter.as_deref(), marker.as_deref(), max_keys, &mut Work::default());
        let actual = compute_listing(&objects, &prefix, delimiter.as_deref(), marker.as_deref(), max_keys);
        prop_assert_eq!(snapshot(actual), snapshot(expected));
    }
}

#[test]
#[ignore = "manual fixed-fixture listing benchmark; no timing assertion"]
fn listing_fixed_fixture_benchmark() {
    use std::hint::black_box;
    use std::time::Instant;
    for total in [1000, 10_000, 100_000] {
        let objects: BTreeMap<_, _> = (0..total)
            .map(|index| {
                let prefix = if index < total - 101 { "a" } else { "z" };
                (format!("{prefix}/{index:09}"), object())
            })
            .collect();
        let mut work = Work::default();
        let expected = reference_listing::<true>(&objects, "z/", None, None, 100, &mut work);
        assert_eq!(
            snapshot(compute_listing(&objects, "z/", None, None, 100)),
            snapshot(expected)
        );
        let mut old_times = Vec::new();
        let mut new_times = Vec::new();
        for _ in 0..7 {
            let start = Instant::now();
            black_box(reference_listing::<false>(
                black_box(&objects),
                "z/",
                None,
                None,
                100,
                &mut Work::default(),
            ));
            old_times.push(start.elapsed().as_nanos());
            let start = Instant::now();
            black_box(compute_listing(black_box(&objects), "z/", None, None, 100));
            new_times.push(start.elapsed().as_nanos());
        }
        old_times.sort_unstable();
        new_times.sort_unstable();
        println!("{{\"fixture\":\"late_prefix\",\"objects\":{total},\"reference_visited\":{},\"reference_median_ns\":{},\"optimized_median_ns\":{}}}", work.visited, old_times[3], new_times[3]);
    }
    let objects: BTreeMap<_, _> = (0..10_000)
        .map(|index| (format!("{:04}/{:04}", index / 10, index % 10), object()))
        .collect();
    let mut work = Work::default();
    let expected = reference_listing::<true>(&objects, "", Some("/"), None, 1000, &mut work);
    let start = Instant::now();
    let actual = compute_listing(&objects, "", Some("/"), None, 1000);
    let elapsed = start.elapsed().as_nanos();
    assert_eq!(snapshot(actual), snapshot(expected));
    assert_eq!(work.prefix_comparisons, 5_004_000);
    println!("{{\"fixture\":\"common_prefixes\",\"objects\":10000,\"reference_prefix_comparisons\":{},\"optimized_elapsed_ns\":{elapsed}}}", work.prefix_comparisons);
}

#[test]
fn listing_caps_results_without_changing_the_requested_max_keys_echo() {
    let objects = (0..1002)
        .map(|index| (format!("key-{index:04}"), object()))
        .collect();
    for requested in [1001, usize::MAX] {
        let result = compute_listing(&objects, "", None, None, requested);
        assert_eq!(result.keys.len(), 1000);
        assert!(result.is_truncated);
        assert_eq!(result.next_token.as_deref(), Some("key-0999"));
        assert_eq!(
            snapshot(result),
            snapshot(reference_listing::<true>(
                &objects,
                "",
                None,
                None,
                requested,
                &mut Work::default()
            ))
        );
    }
    for delimiter in [None, Some("/"), Some("")] {
        let result = compute_listing(&objects, "", delimiter, None, 0);
        assert!(result.keys.is_empty());
        assert!(result.common_prefixes.is_empty());
        assert!(!result.is_truncated);
        assert!(result.next_token.is_none());
    }
}
