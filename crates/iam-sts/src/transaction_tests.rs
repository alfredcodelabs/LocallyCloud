use super::*;
use crate::persistence::IamPersistence;
use locallycloud_state::{StateCipher, StateDb};

const ACCOUNT: &str = "000000000000";
const POLICY: &str = "arn:aws:iam::000000000000:policy/team/writer";
const ALLOW: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"lambda.amazonaws.com"}}]}"#;

fn call(store: &IamStore, action: &str, parameters: &[(&str, &str)]) -> OpResult {
    let body = parameters
        .iter()
        .map(|(key, value)| format!("{key}={}", crate::model::urlencode_doc(value)))
        .collect::<Vec<_>>()
        .join("&");
    let query = QueryRequest::parse(body.as_bytes());
    store.transact_resources(
        ResourceScope::for_operation(ACCOUNT, action, &query),
        |staged| dispatch_iam_store(staged, ACCOUNT, action, &query),
    )
}

struct Fixture {
    root: std::path::PathBuf,
    db: Arc<StateDb>,
    persistence: Arc<IamPersistence>,
    store: IamStore,
}
impl Fixture {
    fn new() -> Self {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/test-state")
            .join(format!("iam-entities-{}", uuid::Uuid::new_v4()));
        let db = Arc::new(StateDb::open(root.join("state.sqlite3")).unwrap());
        let persistence = Arc::new(
            IamPersistence::with_cipher(db.clone(), StateCipher::with_key(&[29; 32])).unwrap(),
        );
        let store = IamStore::durable(persistence.clone()).unwrap();
        call(&store, "CreateUser", &[("UserName", "alice")]).unwrap();
        call(&store, "CreateGroup", &[("GroupName", "team")]).unwrap();
        call(
            &store,
            "CreateRole",
            &[("RoleName", "worker"), ("AssumeRolePolicyDocument", TRUST)],
        )
        .unwrap();
        call(
            &store,
            "CreatePolicy",
            &[
                ("PolicyName", "writer"),
                ("Path", "/team/"),
                ("PolicyDocument", ALLOW),
            ],
        )
        .unwrap();
        Self {
            root,
            db,
            persistence,
            store,
        }
    }
    fn rows(&self) -> Vec<(String, String, String, Vec<u8>)> {
        self.db
            .connection()
            .unwrap()
            .prepare(
                "SELECT account,kind,name,payload FROM iam_resources ORDER BY account,kind,name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }
    fn restored(&self) -> IamStore {
        IamStore::durable(self.persistence.clone()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn related_entities_commit_atomically_and_unchanged_envelopes_are_preserved() {
    let f = Fixture::new();
    let before = f.rows();
    // The group UPSERT sorts before the rejected user UPSERT: neither may survive.
    f.db.connection().unwrap().execute_batch("CREATE TRIGGER reject_user BEFORE INSERT ON iam_resources WHEN NEW.kind='user' BEGIN SELECT RAISE(ABORT,'injected user failure'); END;").unwrap();
    assert!(call(
        &f.store,
        "AddUserToGroup",
        &[("UserName", "alice"), ("GroupName", "team")]
    )
    .is_err());
    assert_eq!(before, f.rows());
    for store in [&f.store, &f.restored()] {
        assert!(store.get_user(ACCOUNT, "alice").unwrap().groups.is_empty());
        assert!(store.get_group(ACCOUNT, "team").unwrap().members.is_empty());
    }
    f.db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_user")
        .unwrap();
    call(
        &f.store,
        "AddUserToGroup",
        &[("UserName", "alice"), ("GroupName", "team")],
    )
    .unwrap();
    call(
        &f.store,
        "AttachGroupPolicy",
        &[("GroupName", "team"), ("PolicyArn", POLICY)],
    )
    .unwrap();
    let restored = f.restored();
    assert_eq!(
        restored.get_user(ACCOUNT, "alice").unwrap().groups,
        vec!["team"]
    );
    assert_eq!(
        restored.get_group(ACCOUNT, "team").unwrap().members,
        vec!["alice"]
    );
    assert_eq!(
        restored
            .get_policy(ACCOUNT, POLICY)
            .unwrap()
            .attachment_count,
        1
    );
    let after = f.rows();
    for row in before.iter().filter(|row| row.1 == "role") {
        assert!(after.contains(row));
    }
    // Attachment and its counter must also roll back together.
    f.db.connection().unwrap().execute_batch("CREATE TRIGGER reject_user BEFORE INSERT ON iam_resources WHEN NEW.kind='user' BEGIN SELECT RAISE(ABORT,'injected user failure'); END;").unwrap();
    assert!(call(
        &f.store,
        "AttachUserPolicy",
        &[("UserName", "alice"), ("PolicyArn", POLICY)]
    )
    .is_err());
    assert_eq!(after, f.rows());
    assert!(f
        .store
        .get_user(ACCOUNT, "alice")
        .unwrap()
        .attached_policies
        .is_empty());
    assert_eq!(
        f.store
            .get_policy(ACCOUNT, POLICY)
            .unwrap()
            .attachment_count,
        1
    );
}

#[test]
fn rename_boundaries_profiles_and_policy_versions_use_their_read_dependencies() {
    let f = Fixture::new();
    // Both the old and new names participate in a rename, including collision checks.
    call(&f.store, "CreateUser", &[("UserName", "taken")]).unwrap();
    assert!(matches!(
        call(
            &f.store,
            "UpdateUser",
            &[("UserName", "alice"), ("NewUserName", "taken")]
        ),
        Err(IamStsError::EntityAlreadyExists(_))
    ));
    call(
        &f.store,
        "UpdateUser",
        &[
            ("UserName", "alice"),
            ("NewUserName", "renamed"),
            ("NewPath", "/team/"),
        ],
    )
    .unwrap();
    assert!(f.store.get_user(ACCOUNT, "alice").is_none());
    assert_eq!(
        f.restored().get_user(ACCOUNT, "renamed").unwrap().arn,
        "arn:aws:iam::000000000000:user/team/renamed"
    );
    call(
        &f.store,
        "PutUserPermissionsBoundary",
        &[("UserName", "renamed"), ("PermissionsBoundary", POLICY)],
    )
    .unwrap();
    call(
        &f.store,
        "CreateRole",
        &[
            ("RoleName", "bounded"),
            ("AssumeRolePolicyDocument", TRUST),
            ("PermissionsBoundary", POLICY),
        ],
    )
    .unwrap();
    call(
        &f.store,
        "CreateInstanceProfile",
        &[("InstanceProfileName", "compute")],
    )
    .unwrap();
    assert!(matches!(
        call(
            &f.store,
            "AddRoleToInstanceProfile",
            &[("InstanceProfileName", "compute"), ("RoleName", "missing")]
        ),
        Err(IamStsError::NoSuchEntity(_))
    ));
    call(
        &f.store,
        "AddRoleToInstanceProfile",
        &[("InstanceProfileName", "compute"), ("RoleName", "bounded")],
    )
    .unwrap();
    call(
        &f.store,
        "CreatePolicyVersion",
        &[
            ("PolicyArn", POLICY),
            ("PolicyDocument", ALLOW),
            ("SetAsDefault", "true"),
        ],
    )
    .unwrap();
    let restored = f.restored();
    assert_eq!(
        restored
            .get_instance_profile(ACCOUNT, "compute")
            .unwrap()
            .role
            .as_deref(),
        Some("bounded")
    );
    assert_eq!(
        restored
            .get_user(ACCOUNT, "renamed")
            .unwrap()
            .permission_boundary
            .as_deref(),
        Some(POLICY)
    );
    assert_eq!(
        restored
            .get_role(ACCOUNT, "bounded")
            .unwrap()
            .permission_boundary
            .as_deref(),
        Some(POLICY)
    );
    assert_eq!(
        restored
            .get_policy(ACCOUNT, POLICY)
            .unwrap()
            .default_version_id,
        "v2"
    );
    // Seeded AWS policies are read from their global account, never copied wholesale.
    iam::seed_aws_managed_policies(&f.store);
    let aws_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole";
    call(
        &f.store,
        "CreateUser",
        &[
            ("UserName", "aws-bounded"),
            ("PermissionsBoundary", aws_policy),
        ],
    )
    .unwrap();
    call(
        &f.store,
        "AttachRolePolicy",
        &[("RoleName", "worker"), ("PolicyArn", aws_policy)],
    )
    .unwrap();
    assert_eq!(
        f.restored()
            .get_user(ACCOUNT, "aws-bounded")
            .unwrap()
            .permission_boundary
            .as_deref(),
        Some(aws_policy)
    );
    assert_eq!(
        f.store
            .get_policy("aws", aws_policy)
            .unwrap()
            .attachment_count,
        0
    );
}

#[test]
fn inventory_size_does_not_expand_staging_and_escaping_changes_fail_closed() {
    let f = Fixture::new();
    for i in 0..1000 {
        let mut user = f.store.get_user(ACCOUNT, "alice").unwrap();
        user.user_name = format!("unrelated-{i}");
        user.inline_policies
            .insert("large".into(), "x".repeat(4096));
        f.store.create_user("111111111111", user);
    }
    let body = format!(
        "UserName=alice&PolicyName=inline&PolicyDocument={}",
        crate::model::urlencode_doc(ALLOW)
    );
    let query = QueryRequest::parse(body.as_bytes());
    let scope = ResourceScope::for_operation(ACCOUNT, "PutUserPolicy", &query);
    f.store
        .transact_resources(scope, |staged| {
            assert_eq!(staged.list_users(ACCOUNT).len(), 1);
            assert!(staged.list_users("111111111111").is_empty());
            assert!(staged.list_policies(ACCOUNT).is_empty());
            dispatch_iam_store(staged, ACCOUNT, "PutUserPolicy", &query)
        })
        .unwrap();
    let before = f.rows();
    let scope = ResourceScope::for_operation(
        ACCOUNT,
        "DeleteUser",
        &QueryRequest::parse(b"UserName=alice"),
    );
    let result = f.store.transact_resources(scope, |staged| {
        staged.remove_user(ACCOUNT, "alice");
        let mut user = f.store.get_user(ACCOUNT, "alice").unwrap();
        user.user_name = "escaped".into();
        staged.create_user(ACCOUNT, user);
        Ok(())
    });
    assert!(matches!(result, Err(IamStsError::InternalFailure(_))));
    assert!(f.store.get_user(ACCOUNT, "alice").is_some());
    assert!(f.store.get_user(ACCOUNT, "escaped").is_none());
    assert_eq!(before, f.rows());
    assert_eq!(f.store.list_users("111111111111").len(), 1000);
}
