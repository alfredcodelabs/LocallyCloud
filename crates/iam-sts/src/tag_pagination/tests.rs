use super::*;
use crate::iam;
use locallycloud_core::handler::ServiceRequest;
use locallycloud_core::registry::{ServiceName, ServiceRegistry};
use std::sync::Arc;

const ACCOUNT: &str = "000000000000";
const KINDS: [TagKind; 4] = [
    TagKind::User,
    TagKind::Role,
    TagKind::Policy,
    TagKind::InstanceProfile,
];

fn fixture() -> IamStore {
    let store = IamStore::new();
    for name in ["first", "other"] {
        iam::create_user(
            &store,
            ACCOUNT,
            &QueryRequest::parse(format!("UserName={name}&Path=/team/").as_bytes()),
        )
        .unwrap();
        iam::create_role(&store, ACCOUNT, &QueryRequest::parse(format!("RoleName={name}&Path=/team/&AssumeRolePolicyDocument={{\"Statement\":{{\"Effect\":\"Allow\",\"Principal\":{{\"Service\":\"ec2.amazonaws.com\"}},\"Action\":\"sts:AssumeRole\"}}}}").as_bytes())).unwrap();
        iam::create_policy(&store, ACCOUNT, &QueryRequest::parse(format!("PolicyName={name}&Path=/team/&PolicyDocument={{\"Statement\":{{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}}}").as_bytes())).unwrap();
        iam::create_instance_profile(
            &store,
            ACCOUNT,
            &QueryRequest::parse(format!("InstanceProfileName={name}&Path=/team/").as_bytes()),
        )
        .unwrap();
    }
    store
}

fn query(kind: TagKind, name: &str, suffix: &str) -> QueryRequest {
    let name = match kind {
        TagKind::Policy => format!("arn:aws:iam::{ACCOUNT}:policy/team/{name}"),
        _ => name.into(),
    };
    QueryRequest::parse(format!("{}={name}{suffix}", kind.parameter()).as_bytes())
}

fn set_tags(store: &IamStore, kind: TagKind, tags: BTreeMap<String, String>) {
    match kind {
        TagKind::User => {
            store.update_user(ACCOUNT, "first", |user| user.tags = tags);
        }
        TagKind::Role => {
            store.update_role(ACCOUNT, "first", |role| role.tags = tags);
        }
        TagKind::Policy => {
            store.update_policy(
                ACCOUNT,
                &format!("arn:aws:iam::{ACCOUNT}:policy/team/first"),
                |policy| policy.tags = tags,
            );
        }
        TagKind::InstanceProfile => {
            store.update_instance_profile(ACCOUNT, "first", |profile| profile.tags = tags);
        }
    }
}

fn elements(xml: &str, name: &str) -> Vec<String> {
    xml.split(&format!("<{name}>"))
        .skip(1)
        .map(|piece| {
            piece
                .split(&format!("</{name}>"))
                .next()
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn assert_validation(error: IamStsError) {
    assert_eq!(error.code(), "ValidationError");
    assert_eq!(error.http_status(), 400);
}

#[test]
fn all_four_tag_lists_page_in_key_order_and_preserve_the_underlying_store() {
    let store = fixture();
    let tags = BTreeMap::from([
        ("a".into(), "first".into()),
        ("Équipe".into(), "équipe".into()),
        ("部署".into(), "開発".into()),
    ]);
    for kind in KINDS {
        set_tags(&store, kind, tags.clone());
        let first = list(&store, ACCOUNT, kind, &query(kind, "first", "&MaxItems=1")).unwrap();
        assert_eq!(elements(&first, "Key"), ["a"]);
        assert!(first.contains("<IsTruncated>true</IsTruncated>"));
        let marker = elements(&first, "Marker").pop().unwrap();
        let second = list(
            &store,
            ACCOUNT,
            kind,
            &query(kind, "first", &format!("&MaxItems=1&Marker={marker}")),
        )
        .unwrap();
        assert_eq!(elements(&second, "Key"), ["Équipe"]);
        let marker = elements(&second, "Marker").pop().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(&marker).unwrap();
        let cursor: (u8, String, String, String, Position) =
            serde_json::from_slice(&decoded).unwrap();
        assert_eq!(cursor.0, 1);
        assert_eq!(cursor.1, ACCOUNT);
        assert_eq!(cursor.2, kind.operation());
        assert_eq!(cursor.4, Position::Key("Équipe".into()));
        let last = list(
            &store,
            ACCOUNT,
            kind,
            &query(kind, "first", &format!("&MaxItems=1&Marker={marker}")),
        )
        .unwrap();
        assert_eq!(elements(&last, "Key"), ["部署"]);
        assert!(last.contains("<IsTruncated>false</IsTruncated>"));
        assert!(!last.contains("<Marker>"));
        let default_page = list(&store, ACCOUNT, kind, &query(kind, "first", "")).unwrap();
        assert_eq!(elements(&default_page, "Key"), ["a", "Équipe", "部署"]);
        let name = query(kind, "first", "");
        let actual = store
            .read_tags(
                ACCOUNT,
                kind,
                name.require(kind.parameter()).unwrap(),
                |_, tags| Ok(tags.clone()),
            )
            .unwrap();
        assert_eq!(actual, tags);
    }
}

#[test]
fn every_legacy_tag_is_reachable_even_when_more_than_fifty_are_stored() {
    let store = fixture();
    let expected: BTreeMap<String, String> = (0..121)
        .map(|index| (format!("key-{index:03}"), format!("value-{index}")))
        .collect();
    for kind in KINDS {
        set_tags(&store, kind, expected.clone());
        for maximum in [None, Some(1), Some(37), Some(1000)] {
            let mut marker = None;
            let mut seen = Vec::new();
            let mut pages = 0;
            loop {
                let mut suffix = maximum
                    .map(|maximum| format!("&MaxItems={maximum}"))
                    .unwrap_or_default();
                if let Some(marker) = marker {
                    suffix.push_str(&format!("&Marker={marker}"));
                }
                let page = list(&store, ACCOUNT, kind, &query(kind, "first", &suffix)).unwrap();
                let keys = elements(&page, "Key");
                assert!(!keys.is_empty());
                assert!(keys.len() <= maximum.unwrap_or(100).min(50));
                seen.extend(keys);
                pages += 1;
                assert!(pages <= 121);
                marker = elements(&page, "Marker").pop();
                assert_eq!(
                    page.contains("<IsTruncated>true</IsTruncated>"),
                    marker.is_some()
                );
                if marker.is_none() {
                    break;
                }
            }
            assert_eq!(seen, expected.keys().cloned().collect::<Vec<_>>());
        }
    }
}

#[test]
fn maximums_and_cursors_are_checked_for_format_version_account_operation_and_resource() {
    let store = fixture();
    for kind in KINDS {
        set_tags(
            &store,
            kind,
            BTreeMap::from([("a".into(), "one".into()), ("b".into(), "two".into())]),
        );
        for maximum in ["", "0", "1001", "-1", "invalid", "184467440737095516160"] {
            assert_validation(
                list(
                    &store,
                    ACCOUNT,
                    kind,
                    &query(kind, "first", &format!("&MaxItems={maximum}")),
                )
                .unwrap_err(),
            );
        }
        let page = list(&store, ACCOUNT, kind, &query(kind, "first", "&MaxItems=1")).unwrap();
        let marker = elements(&page, "Marker").pop().unwrap();
        assert_validation(
            list(
                &store,
                ACCOUNT,
                kind,
                &query(kind, "other", &format!("&Marker={marker}")),
            )
            .unwrap_err(),
        );
        assert_validation(
            list(
                &store,
                "111111111111",
                kind,
                &query(kind, "first", &format!("&Marker={marker}")),
            )
            .unwrap_err(),
        );
        let other = match kind {
            TagKind::User => TagKind::Role,
            _ => TagKind::User,
        };
        assert_validation(
            list(
                &store,
                ACCOUNT,
                other,
                &query(other, "first", &format!("&Marker={marker}")),
            )
            .unwrap_err(),
        );
        for marker in [
            String::new(),
            "invalid*".into(),
            "é".into(),
            "a".repeat(MAX_MARKER_BYTES + 1),
            URL_SAFE_NO_PAD.encode(b"not-json"),
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&(
                    2u8,
                    ACCOUNT,
                    kind.operation(),
                    "arn",
                    Position::Key("a".into()),
                ))
                .unwrap(),
            ),
            URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&(
                    1u8,
                    ACCOUNT,
                    kind.operation(),
                    "arn",
                    Position::Key(String::new()),
                ))
                .unwrap(),
            ),
        ] {
            assert_validation(
                list(
                    &store,
                    ACCOUNT,
                    kind,
                    &query(kind, "first", &format!("&Marker={marker}")),
                )
                .unwrap_err(),
            );
        }
    }
}

#[test]
fn cursor_survives_removal_of_its_last_key_without_replaying_previous_tags() {
    let store = fixture();
    let kind = TagKind::User;
    set_tags(
        &store,
        kind,
        BTreeMap::from([
            ("a".into(), "one".into()),
            ("b".into(), "two".into()),
            ("c".into(), "three".into()),
        ]),
    );
    let first = list(&store, ACCOUNT, kind, &query(kind, "first", "&MaxItems=1")).unwrap();
    let marker = elements(&first, "Marker").pop().unwrap();
    store.update_user(ACCOUNT, "first", |user| {
        user.tags.remove("a");
    });
    let remaining = list(
        &store,
        ACCOUNT,
        kind,
        &query(kind, "first", &format!("&Marker={marker}")),
    )
    .unwrap();
    assert_eq!(elements(&remaining, "Key"), ["b", "c"]);
}

#[tokio::test]
async fn native_query_errors_are_sdk_readable_and_aws_managed_policy_tag_lists_are_rejected() {
    let store = Arc::new(fixture());
    iam::seed_aws_managed_policies(&store);
    let registry = ServiceRegistry::with_known_services();
    crate::register_with_store_and_mode(
        &registry,
        store,
        Arc::new(crate::sts::SessionStore::new()),
        crate::enforcement::EnforcementMode::Permissive,
    );
    let handler = registry
        .lookup(&ServiceName::new("iam"))
        .unwrap()
        .handler
        .unwrap();
    for kind in KINDS {
        let q = query(kind, "first", "&MaxItems=0");
        let body = format!(
            "Action={}&{}={}&MaxItems=0",
            kind.operation(),
            kind.parameter(),
            q.require(kind.parameter()).unwrap()
        );
        let response = handler
            .handle(ServiceRequest {
                method: http::Method::POST,
                uri: "/".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: bytes::Bytes::from(body),
                account_id: ACCOUNT.into(),
                region: "us-east-1".into(),
                request_id: "tag-page-invalid".into(),
            })
            .await;
        assert_eq!(response.status(), 400);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let xml = std::str::from_utf8(&body).unwrap();
        assert!(xml.contains("<Code>ValidationError</Code>"));
        assert!(xml.contains("<RequestId>tag-page-invalid</RequestId>"));
    }
    let error = list(
        &fixture_with_managed_policy(),
        ACCOUNT,
        TagKind::Policy,
        &QueryRequest::parse(
            b"PolicyArn=arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), "InvalidInput");
    assert_eq!(error.http_status(), 400);
}

fn fixture_with_managed_policy() -> IamStore {
    let store = IamStore::new();
    iam::seed_aws_managed_policies(&store);
    store
}

#[test]
fn legacy_oversized_keys_use_a_bounded_offset_cursor_without_losing_tags() {
    let store = fixture();
    let huge_key = "m".repeat(MAX_MARKER_BYTES * 2);
    let mut expected: BTreeMap<String, String> = (0..49)
        .map(|index| (format!("a-{index:03}"), index.to_string()))
        .collect();
    expected.insert(huge_key.clone(), "legacy-value".into());
    expected.extend((0..71).map(|index| (format!("z-{index:03}"), index.to_string())));
    for kind in KINDS {
        set_tags(&store, kind, expected.clone());
        let first = list(&store, ACCOUNT, kind, &query(kind, "first", "")).unwrap();
        let marker = elements(&first, "Marker").pop().unwrap();
        assert!(marker.len() < MAX_MARKER_BYTES);
        let decoded = URL_SAFE_NO_PAD.decode(&marker).unwrap();
        let cursor: (u8, String, String, String, Position) =
            serde_json::from_slice(&decoded).unwrap();
        assert_eq!(cursor.4, Position::Offset(50));
        assert!(!std::str::from_utf8(&decoded).unwrap().contains(&huge_key));
        let mut seen = elements(&first, "Key");
        let second = list(
            &store,
            ACCOUNT,
            kind,
            &query(kind, "first", &format!("&Marker={marker}")),
        )
        .unwrap();
        seen.extend(elements(&second, "Key"));
        let marker = elements(&second, "Marker").pop().unwrap();
        let cursor: (u8, String, String, String, Position) =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&marker).unwrap()).unwrap();
        assert!(matches!(cursor.4, Position::Key(_)));
        let third = list(
            &store,
            ACCOUNT,
            kind,
            &query(kind, "first", &format!("&Marker={marker}")),
        )
        .unwrap();
        seen.extend(elements(&third, "Key"));
        assert!(!third.contains("<Marker>"));
        assert_eq!(seen, expected.keys().cloned().collect::<Vec<_>>());
        let bad = encode_cursor(
            ACCOUNT,
            kind,
            &cursor.3,
            &Position::Offset(expected.len() + 1),
        )
        .unwrap();
        assert_validation(
            list(
                &store,
                ACCOUNT,
                kind,
                &query(kind, "first", &format!("&Marker={bad}")),
            )
            .unwrap_err(),
        );
        let name = query(kind, "first", "");
        assert_eq!(
            store
                .read_tags(
                    ACCOUNT,
                    kind,
                    name.require(kind.parameter()).unwrap(),
                    |_, tags| Ok(tags.clone())
                )
                .unwrap(),
            expected
        );
    }
}

#[test]
fn legacy_empty_keys_remain_readable_through_the_offset_fallback() {
    let store = fixture();
    let kind = TagKind::User;
    set_tags(
        &store,
        kind,
        BTreeMap::from([
            (String::new(), "legacy".into()),
            ("next".into(), "value".into()),
        ]),
    );
    let first = list(&store, ACCOUNT, kind, &query(kind, "first", "&MaxItems=1")).unwrap();
    assert_eq!(elements(&first, "Key"), [""]);
    let marker = elements(&first, "Marker").pop().unwrap();
    let second = list(
        &store,
        ACCOUNT,
        kind,
        &query(kind, "first", &format!("&Marker={marker}")),
    )
    .unwrap();
    assert_eq!(elements(&second, "Key"), ["next"]);
    assert!(!second.contains("<Marker>"));
}
