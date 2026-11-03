use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
const ACCOUNT: &str = "111111111111";
const REGION: &str = "us-east-1";
fn call(service: &KmsService, operation: &str, value: Value) -> Result<Value, KmsError> {
    service.dispatch(operation, value.as_object().unwrap(), ACCOUNT, REGION)
}
fn clock_service(db: Arc<StateDb>, clock: Arc<AtomicU64>) -> KmsService {
    KmsService::with_clock(
        db,
        Arc::new(move || Ok(clock.load(Ordering::SeqCst) as f64)),
    )
    .unwrap()
}
#[test]
fn automatic_rotation_retains_old_ciphertext_and_schedule_across_restart() {
    let db = crate::test_db();
    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let service = clock_service(db.clone(), clock.clone());
    let created = call(
        &service,
        "CreateKey",
        json!({"Tags":[{"TagKey":"owner","TagValue":"ledger"}]}),
    )
    .unwrap();
    let id = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    let context = json!({"tenant":"ledger"});
    let encrypt = || {
        call(&service,"Encrypt",json!({"KeyId":id,"Plaintext":STANDARD.encode("old ledger"),"EncryptionContext":context})).unwrap()
    };
    let old = encrypt();
    call(
        &service,
        "EnableKeyRotation",
        json!({"KeyId":id,"RotationPeriodInDays":90}),
    )
    .unwrap();
    let status = call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap();
    assert_eq!(status["RotationPeriodInDays"], 90);
    let due = status["NextRotationDate"].as_f64().unwrap();
    clock.fetch_add(50, Ordering::SeqCst);
    call(
        &service,
        "EnableKeyRotation",
        json!({"KeyId":id,"RotationPeriodInDays":90}),
    )
    .unwrap();
    assert_eq!(
        call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap()["NextRotationDate"],
        json!(due)
    );
    clock.store(due as u64, Ordering::SeqCst);
    let encrypted = std::thread::scope(|threads| {
        let jobs: Vec<_> = (0..8).map(|_| threads.spawn(encrypt)).collect();
        jobs.into_iter()
            .map(|job| job.join().unwrap())
            .collect::<Vec<_>>()
    });
    let new = encrypted.first().unwrap();
    let version = |value: &Value| {
        crypto::parse_envelope(
            &STANDARD
                .decode(value["CiphertextBlob"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
        .material_version
    };
    assert_eq!(version(&old), 1);
    assert_eq!(version(new), 2);
    let scope = Scope::new(ACCOUNT, REGION);
    service
        .store
        .with_key(&scope, id, |key| {
            assert_eq!(key.historical_materials.len(), 1);
            assert_ne!(
                key.material.expose(),
                key.historical_materials.get(&1).unwrap().expose()
            );
            assert_eq!(key.tags.get("owner").unwrap(), "ledger");
        })
        .unwrap();
    drop(service);
    let restarted = clock_service(db, clock.clone());
    for ciphertext in [&old, new] {
        let plain = call(
            &restarted,
            "Decrypt",
            json!({"CiphertextBlob":ciphertext["CiphertextBlob"],"EncryptionContext":context}),
        )
        .unwrap();
        assert_eq!(
            STANDARD
                .decode(plain["Plaintext"].as_str().unwrap())
                .unwrap(),
            b"old ledger"
        );
        assert!(call(&restarted,"Decrypt",json!({"CiphertextBlob":ciphertext["CiphertextBlob"],"EncryptionContext":{"tenant":"other"}})).is_err());
    }
    assert!(
        call(&restarted, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap()["NextRotationDate"]
            .as_f64()
            .unwrap()
            > due
    );
    assert!(call(
        &restarted,
        "GetKeyRotationStatus",
        json!({"KeyId":format!("arn:aws:kms:us-east-2:{ACCOUNT}:key/{id}")})
    )
    .is_err());
    let next = call(&restarted, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap()
        ["NextRotationDate"]
        .as_f64()
        .unwrap();
    clock.store(next as u64, Ordering::SeqCst);
    call(
        &restarted,
        "Decrypt",
        json!({"CiphertextBlob":old["CiphertextBlob"],"EncryptionContext":context}),
    )
    .unwrap();
    restarted
        .store
        .with_key(&scope, id, |key| assert_eq!(key.material_version, 3))
        .unwrap();
}
#[test]
fn on_demand_quota_disable_lifecycle_and_failed_commit_are_atomic() {
    let db = crate::test_db();
    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let service = clock_service(db.clone(), clock.clone());
    let created = call(&service, "CreateKey", json!({})).unwrap();
    let id = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    for period in [89, 2561] {
        assert!(call(
            &service,
            "EnableKeyRotation",
            json!({"KeyId":id,"RotationPeriodInDays":period})
        )
        .is_err());
    }
    call(&service, "EnableKeyRotation", json!({"KeyId":id})).unwrap();
    let before = call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap();
    db.connection().unwrap().execute_batch("CREATE TRIGGER reject_rotation BEFORE UPDATE ON kms_keys BEGIN SELECT RAISE(ABORT,'rotation commit failed'); END;").unwrap();
    assert!(call(&service, "RotateKeyOnDemand", json!({"KeyId":id})).is_err());
    service
        .store
        .with_key(&Scope::new(ACCOUNT, REGION), id, |key| {
            assert_eq!(key.material_version, 1)
        })
        .unwrap();
    db.connection()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_rotation;")
        .unwrap();
    clock.store(
        before["NextRotationDate"].as_f64().unwrap() as u64 - 600,
        Ordering::SeqCst,
    );
    assert!(matches!(
        call(&service, "RotateKeyOnDemand", json!({"KeyId":id})),
        Err(KmsError::Conflict)
    ));
    clock.store(1_700_000_000, Ordering::SeqCst);
    for _ in 0..25 {
        call(&service, "RotateKeyOnDemand", json!({"KeyId":id})).unwrap();
    }
    assert!(matches!(
        call(&service, "RotateKeyOnDemand", json!({"KeyId":id})),
        Err(KmsError::LimitExceeded)
    ));
    assert_eq!(
        call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap(),
        before
    );
    call(&service, "DisableKey", json!({"KeyId":id})).unwrap();
    clock.store(
        before["NextRotationDate"].as_f64().unwrap() as u64 + 10,
        Ordering::SeqCst,
    );
    assert_eq!(
        call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap()["KeyRotationEnabled"],
        true
    );
    assert!(matches!(
        call(&service, "RotateKeyOnDemand", json!({"KeyId":id})),
        Err(KmsError::Disabled)
    ));
    service
        .store
        .with_key(&Scope::new(ACCOUNT, REGION), id, |key| {
            assert_eq!(key.material_version, 26)
        })
        .unwrap();
    call(&service, "EnableKey", json!({"KeyId":id})).unwrap();
    call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap();
    service
        .store
        .with_key(&Scope::new(ACCOUNT, REGION), id, |key| {
            assert_eq!(key.material_version, 27)
        })
        .unwrap();
    call(&service, "DisableKeyRotation", json!({"KeyId":id})).unwrap();
    assert_eq!(
        call(&service, "GetKeyRotationStatus", json!({"KeyId":id})).unwrap()["KeyRotationEnabled"],
        false
    );
    call(
        &service,
        "ScheduleKeyDeletion",
        json!({"KeyId":id,"PendingWindowInDays":7}),
    )
    .unwrap();
    assert!(call(&service, "EnableKeyRotation", json!({"KeyId":id})).is_err());
}

#[test]
fn legacy_customer_and_managed_records_restore_with_real_rotation_defaults() {
    let db = crate::test_db();
    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let service = clock_service(db.clone(), clock.clone());
    let created = call(&service, "CreateKey", json!({})).unwrap();
    let customer = created["KeyMetadata"]["KeyId"].as_str().unwrap();
    let scope = Scope::new(ACCOUNT, REGION);
    let managed = service.service_default_key(&scope, "s3").unwrap();
    assert_eq!(
        call(&service, "GetKeyRotationStatus", json!({"KeyId":managed})).unwrap()
            ["KeyRotationEnabled"],
        true
    );
    assert!(matches!(
        call(&service, "DisableKeyRotation", json!({"KeyId":managed})),
        Err(KmsError::Unsupported)
    ));
    drop(service);
    for id in [customer, &managed] {
        let connection = db.connection().unwrap();
        let saved: Vec<u8> = connection
            .query_row("SELECT record FROM kms_keys WHERE key_id=?1", [id], |row| {
                row.get(0)
            })
            .unwrap();
        let mut value: Value = serde_json::from_slice(&saved).unwrap();
        value.as_object_mut().unwrap().remove("rotation");
        value
            .as_object_mut()
            .unwrap()
            .remove("historical_materials");
        if id == managed {
            value["creation_date"] = json!(1_600_000_000.0);
        }
        connection
            .execute(
                "UPDATE kms_keys SET record=?2 WHERE key_id=?1",
                rusqlite::params![id, serde_json::to_vec(&value).unwrap()],
            )
            .unwrap();
    }
    let reopened = clock_service(db.clone(), clock);
    assert_eq!(
        call(&reopened, "GetKeyRotationStatus", json!({"KeyId":customer})).unwrap()
            ["KeyRotationEnabled"],
        false
    );
    assert_eq!(
        call(&reopened, "GetKeyRotationStatus", json!({"KeyId":managed})).unwrap()
            ["KeyRotationEnabled"],
        true
    );
    reopened
        .store
        .with_key(&scope, &managed, |key| {
            assert_eq!(key.material_version, 2);
            assert_eq!(key.historical_materials.len(), 1);
        })
        .unwrap();
    drop(reopened);
    let connection = db.connection().unwrap();
    let saved: Vec<u8> = connection
        .query_row(
            "SELECT record FROM kms_keys WHERE key_id=?1",
            [&managed],
            |row| row.get(0),
        )
        .unwrap();
    let mut value: Value = serde_json::from_slice(&saved).unwrap();
    let material = value["historical_materials"]
        .as_object_mut()
        .unwrap()
        .remove("1")
        .unwrap();
    value["material_version"] = json!(3);
    value["historical_materials"] = json!({"1":value["sealed_material"],"2":material});
    connection
        .execute(
            "UPDATE kms_keys SET record=?2 WHERE key_id=?1",
            rusqlite::params![managed, serde_json::to_vec(&value).unwrap()],
        )
        .unwrap();
    assert!(
        KmsService::new(db).is_err(),
        "history generations must authenticate their version, not only their key ID"
    );
}

#[test]
fn synchronous_validation_leaves_due_rotation_to_crypto_for_customer_and_managed_keys() {
    let clock = Arc::new(AtomicU64::new(1_700_000_000));
    let service = clock_service(crate::test_db(), clock.clone());
    let created = call(&service, "CreateKey", json!({})).unwrap();
    let customer = created["KeyMetadata"]["KeyId"].as_str().unwrap().to_owned();
    call(
        &service,
        "EnableKeyRotation",
        json!({"KeyId":customer,"RotationPeriodInDays":90}),
    )
    .unwrap();
    let scope = Scope::new(ACCOUNT, REGION);
    let managed = service.service_default_key(&scope, "s3").unwrap();
    clock.fetch_add(366 * 86400, Ordering::SeqCst);
    let context = KmsCallContext {
        source_service: "s3".into(),
        account_id: ACCOUNT.into(),
        region: REGION.into(),
        request_id: "sync-validation".into(),
        caller_arn: Some(format!("arn:aws:iam::{ACCOUNT}:root")),
        iam_policy_allowed: true,
        iam_policy_denied: false,
    };
    for (selector, id) in [
        (customer.as_str(), customer.as_str()),
        ("alias/aws/s3", managed.as_str()),
    ] {
        service
            .validate_key_internal(KmsValidateKeyRequest {
                call: context.clone(),
                key_id: selector.into(),
            })
            .unwrap();
        service
            .store
            .with_key(&scope, id, |key| {
                assert_eq!(key.material_version, 1);
                assert!(key.historical_materials.is_empty());
            })
            .unwrap();
        let generated = service
            .generate_data_key_internal(KmsGenerateDataKeyRequest {
                call: context.clone(),
                key_id: selector.into(),
                number_of_bytes: 32,
                encryption_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(
            crypto::parse_envelope(generated.ciphertext.as_slice())
                .unwrap()
                .material_version,
            2
        );
        service
            .store
            .with_key(&scope, id, |key| assert_eq!(key.material_version, 2))
            .unwrap();
    }
}
