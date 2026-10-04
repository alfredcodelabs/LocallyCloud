use super::*;
use locallycloud_core::integration::kms::{KmsServiceKey, KmsValidateKeyRequest};

fn test_service() -> KmsService {
    KmsService::new(crate::test_db()).expect("KMS service")
}

const ACCOUNT: &str = "000000000000";
const REGION: &str = "us-east-1";

fn body(value: Value) -> Map<String, Value> {
    value.as_object().expect("test body is an object").clone()
}

fn call(
    service: &KmsService,
    operation: &str,
    value: Value,
    account: &str,
    region: &str,
) -> Result<Value, KmsError> {
    service.dispatch(operation, &body(value), account, region)
}

fn call_ok(service: &KmsService, operation: &str, value: Value) -> Value {
    match call(service, operation, value, ACCOUNT, REGION) {
        Ok(value) => value,
        Err(_) => panic!("{operation} unexpectedly failed"),
    }
}

fn create_key(service: &KmsService, account: &str, region: &str) -> (String, String) {
    let result = match call(service, "CreateKey", json!({}), account, region) {
        Ok(value) => value,
        Err(_) => panic!("CreateKey unexpectedly failed"),
    };
    (
        result["KeyMetadata"]["KeyId"]
            .as_str()
            .expect("key id")
            .to_owned(),
        result["KeyMetadata"]["Arn"]
            .as_str()
            .expect("key arn")
            .to_owned(),
    )
}

fn internal_call(account: &str, region: &str) -> KmsCallContext {
    KmsCallContext {
        source_service: "s3".to_owned(),
        account_id: account.to_owned(),
        region: region.to_owned(),
        request_id: "request-id".to_owned(),
        caller_arn: None,
        iam_policy_allowed: false,
        iam_policy_denied: false,
    }
}

#[test]
fn explicit_service_policy_gates_internal_data_keys_and_decrypt() {
    let service = test_service();
    let (key_id, _) = create_key(&service, ACCOUNT, REGION);
    let policy = json!({
            "Statement": [
                {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"},
                {"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},"Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*"}
            ]
        }).to_string();
    call_ok(
        &service,
        "PutKeyPolicy",
        json!({"KeyId":key_id,"Policy":policy}),
    );
    let mut allowed_call = internal_call(ACCOUNT, REGION);
    allowed_call.source_service = "events".to_owned();
    allowed_call.caller_arn = Some("events.amazonaws.com".to_owned());
    let denied = service.generate_data_key_internal(KmsGenerateDataKeyRequest {
        call: internal_call(ACCOUNT, REGION),
        key_id: key_id.clone(),
        number_of_bytes: 32,
        encryption_context: BTreeMap::new(),
    });
    assert!(matches!(denied, Err(KmsError::AccessDenied)));
    let result = service
        .generate_data_key_internal(KmsGenerateDataKeyRequest {
            call: allowed_call.clone(),
            key_id: key_id.clone(),
            number_of_bytes: 32,
            encryption_context: BTreeMap::new(),
        })
        .expect("service principal is allowed");
    assert_eq!(result.plaintext.as_slice().len(), 32);
    let decrypted = service
        .decrypt_internal(KmsDecryptRequest {
            call: allowed_call,
            key_id: Some(key_id),
            ciphertext: result.ciphertext,
            encryption_context: BTreeMap::new(),
        })
        .expect("service principal may decrypt");
    assert_eq!(decrypted.plaintext.as_slice(), result.plaintext.as_slice());
}

#[test]
fn alias_crud_retarget_list_and_scope_are_stable() {
    let service = test_service();
    let (first_id, _) = create_key(&service, ACCOUNT, REGION);
    let (second_id, second_arn) = create_key(&service, ACCOUNT, REGION);

    for (alias, target) in [("alias/zeta", &first_id), ("alias/alpha", &first_id)] {
        assert_eq!(
            call_ok(
                &service,
                "CreateAlias",
                json!({ "AliasName": alias, "TargetKeyId": target })
            ),
            json!({})
        );
    }
    assert!(matches!(
        call(
            &service,
            "CreateAlias",
            json!({ "AliasName": "alias/alpha", "TargetKeyId": first_id }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::AlreadyExists)
    ));
    for alias in ["alpha", "alias/", "alias/aws/reserved", "alias/has space"] {
        assert!(matches!(
            call(
                &service,
                "CreateAlias",
                json!({ "AliasName": alias, "TargetKeyId": second_id }),
                ACCOUNT,
                REGION
            ),
            Err(KmsError::InvalidAliasName)
        ));
    }

    assert!(matches!(
        call(
            &service,
            "CreateAlias",
            json!({ "AliasName": format!("alias/{}", "a".repeat(251)), "TargetKeyId": second_id }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::LimitExceeded)
    ));

    let listed = call_ok(&service, "ListAliases", json!({}));
    assert_eq!(listed["Truncated"], false);
    assert_eq!(listed["Aliases"][0]["AliasName"], "alias/alpha");
    assert_eq!(listed["Aliases"][1]["AliasName"], "alias/zeta");
    let creation_date = listed["Aliases"][0]["CreationDate"].clone();

    call_ok(
        &service,
        "UpdateAlias",
        json!({ "AliasName": "alias/alpha", "TargetKeyId": second_arn }),
    );
    let filtered = call_ok(&service, "ListAliases", json!({ "KeyId": second_id }));
    assert_eq!(filtered["Aliases"].as_array().expect("aliases").len(), 1);
    assert_eq!(filtered["Aliases"][0]["AliasName"], "alias/alpha");
    assert_eq!(filtered["Aliases"][0]["CreationDate"], creation_date);

    let alias_arn = format!("arn:aws:kms:{REGION}:{ACCOUNT}:alias/alpha");
    for key_id in ["alias/alpha", alias_arn.as_str()] {
        let described = call_ok(&service, "DescribeKey", json!({ "KeyId": key_id }));
        assert_eq!(described["KeyMetadata"]["Arn"], second_arn);
    }

    let other_region = "eu-west-1";
    let (other_key_id, _) = create_key(&service, ACCOUNT, other_region);
    assert!(call(
        &service,
        "CreateAlias",
        json!({ "AliasName": "alias/alpha", "TargetKeyId": other_key_id }),
        ACCOUNT,
        other_region
    )
    .is_ok());
    assert_eq!(
        call(&service, "ListAliases", json!({}), "111111111111", REGION).expect("list aliases")
            ["Aliases"],
        json!([])
    );
    assert!(matches!(
        call(
            &service,
            "DescribeKey",
            json!({ "KeyId": alias_arn }),
            "111111111111",
            REGION
        ),
        Err(KmsError::NotFound)
    ));

    call_ok(
        &service,
        "DeleteAlias",
        json!({ "AliasName": "alias/alpha" }),
    );
    assert!(matches!(
        call(
            &service,
            "DescribeKey",
            json!({ "KeyId": "alias/alpha" }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::NotFound)
    ));
    assert_eq!(
        call_ok(&service, "DescribeKey", json!({ "KeyId": second_id }))["KeyMetadata"]["Arn"],
        second_arn
    );
}

#[test]
fn aliases_work_for_crypto_deletion_and_internal_validation() {
    let service = test_service();
    let (key_id, key_arn) = create_key(&service, ACCOUNT, REGION);
    call_ok(
        &service,
        "CreateAlias",
        json!({ "AliasName": "alias/data", "TargetKeyId": key_id }),
    );
    let alias_arn = format!("arn:aws:kms:{REGION}:{ACCOUNT}:alias/data");

    let encrypted = call_ok(
        &service,
        "Encrypt",
        json!({
            "KeyId": "alias/data",
            "Plaintext": STANDARD.encode(b"secret")
        }),
    );
    assert_eq!(encrypted["KeyId"], key_arn);
    let decrypted = call_ok(
        &service,
        "Decrypt",
        json!({
            "CiphertextBlob": encrypted["CiphertextBlob"],
            "KeyId": alias_arn
        }),
    );
    assert_eq!(decrypted["KeyId"], key_arn);
    assert_eq!(decrypted["Plaintext"], STANDARD.encode(b"secret"));

    for selector in [
        key_id.as_str(),
        key_arn.as_str(),
        "alias/data",
        alias_arn.as_str(),
    ] {
        let validated = service
            .validate_key_internal(KmsValidateKeyRequest {
                call: internal_call(ACCOUNT, REGION),
                key_id: selector.to_owned(),
            })
            .expect("enabled key selector validates");
        assert_eq!(validated.key_arn, key_arn);
    }

    let scheduled = call_ok(
        &service,
        "ScheduleKeyDeletion",
        json!({ "KeyId": "alias/data", "PendingWindowInDays": 7 }),
    );
    assert_eq!(scheduled["KeyId"], key_arn);
    assert!(matches!(
        service.validate_key_internal(KmsValidateKeyRequest {
            call: internal_call(ACCOUNT, REGION),
            key_id: key_arn,
        }),
        Err(KmsError::InvalidState)
    ));
}

#[test]
fn aliases_require_existing_enabled_customer_managed_targets() {
    let service = test_service();
    assert!(matches!(
        call(
            &service,
            "CreateAlias",
            json!({ "AliasName": "alias/missing", "TargetKeyId": "missing" }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::NotFound)
    ));

    let default = service
        .encrypt_internal(KmsEncryptRequest {
            call: KmsCallContext {
                source_service: "ssm".to_owned(),
                ..internal_call(ACCOUNT, REGION)
            },
            key: KmsKeySelector::ServiceDefault(KmsServiceKey::Ssm),
            plaintext: SensitiveBytes::new(b"secret".to_vec()),
            encryption_context: BTreeMap::new(),
        })
        .expect("default key is created");
    let described = call_ok(&service, "DescribeKey", json!({ "KeyId": "alias/aws/ssm" }));
    assert_eq!(described["KeyMetadata"]["Arn"], default.key_id);
    assert_eq!(described["KeyMetadata"]["KeyManager"], "AWS");
    let listed = call_ok(&service, "ListAliases", json!({ "KeyId": default.key_id }));
    assert_eq!(listed["Aliases"][0]["AliasName"], "alias/aws/ssm");
    for operation in ["UpdateAlias", "DeleteAlias"] {
        assert!(matches!(
            call(
                &service,
                operation,
                if operation == "UpdateAlias" {
                    json!({ "AliasName": "alias/aws/ssm", "TargetKeyId": default.key_id })
                } else {
                    json!({ "AliasName": "alias/aws/ssm" })
                },
                ACCOUNT,
                REGION
            ),
            Err(KmsError::InvalidAliasName)
        ));
    }
    assert!(matches!(
        service.encrypt_internal(KmsEncryptRequest {
            call: KmsCallContext {
                source_service: "secretsmanager".to_owned(),
                ..internal_call(ACCOUNT, REGION)
            },
            key: KmsKeySelector::Explicit("alias/aws/ssm".to_owned()),
            plaintext: SensitiveBytes::new(b"cross-service".to_vec()),
            encryption_context: BTreeMap::new(),
        }),
        Err(KmsError::AccessDenied)
    ));
    assert!(matches!(
        call(
            &service,
            "CreateAlias",
            json!({ "AliasName": "alias/default", "TargetKeyId": default.key_id }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::AccessDenied)
    ));

    let (key_id, _) = create_key(&service, ACCOUNT, REGION);
    call_ok(
        &service,
        "ScheduleKeyDeletion",
        json!({ "KeyId": key_id, "PendingWindowInDays": 7 }),
    );
    assert!(matches!(
        call(
            &service,
            "CreateAlias",
            json!({ "AliasName": "alias/pending", "TargetKeyId": key_id }),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::InvalidState)
    ));
}

#[test]
fn keys_aliases_defaults_and_policy_survive_restart() {
    let db = crate::test_db();
    let service = KmsService::new(db.clone()).expect("first start");
    let (key_id, _) = create_key(&service, ACCOUNT, REGION);
    let policy = call_ok(&service, "GetKeyPolicy", json!({"KeyId":key_id}))["Policy"]
        .as_str()
        .unwrap()
        .to_owned();
    call_ok(
        &service,
        "CreateAlias",
        json!({"AliasName":"alias/persistent","TargetKeyId":key_id}),
    );
    let default_id = service
        .service_default_key(&Scope::new(ACCOUNT, REGION), "ssm")
        .expect("default key");
    drop(service);
    let reopened = KmsService::new(db).expect("restart");
    let scope = Scope::new(ACCOUNT, REGION);
    assert_eq!(
        reopened.store.alias_target(&scope, "alias/persistent"),
        Some(key_id.clone())
    );
    assert_eq!(
        reopened.store.alias_target(&scope, "alias/aws/ssm"),
        Some(default_id.clone())
    );
    assert_eq!(
        reopened.service_default_key(&scope, "ssm").unwrap(),
        default_id
    );
    assert_eq!(
        call_ok(&reopened, "GetKeyPolicy", json!({"KeyId":key_id}))["Policy"],
        policy
    );
}

#[test]
fn rotation_status_is_disabled_for_new_keys_and_scoped() {
    let service = test_service();
    let (key_id, _) = create_key(&service, ACCOUNT, REGION);
    assert_eq!(
        call_ok(&service, "GetKeyRotationStatus", json!({ "KeyId": key_id })),
        json!({ "KeyRotationEnabled": false })
    );
    assert!(matches!(
        call(
            &service,
            "GetKeyRotationStatus",
            json!({ "KeyId": key_id }),
            ACCOUNT,
            "eu-west-1"
        ),
        Err(KmsError::NotFound)
    ));
}

#[test]
fn s3_default_and_customer_keys_enforce_context_and_revocation() {
    let service = test_service();
    let object = "arn:aws:s3:::orders/Invoice.pdf".to_string();
    let context = BTreeMap::from([("aws:s3:arn".into(), object.clone())]);
    let user = format!("arn:aws:iam::{ACCOUNT}:user/alice");
    let caller = KmsCallContext {
        caller_arn: Some(user.clone()),
        ..internal_call(ACCOUNT, REGION)
    };
    let managed = service
        .validate_key_internal(KmsValidateKeyRequest {
            call: caller.clone(),
            key_id: "alias/aws/s3".into(),
        })
        .unwrap();
    assert_eq!(
        call_ok(&service, "DescribeKey", json!({"KeyId":"alias/aws/s3"}))["KeyMetadata"]
            ["KeyManager"],
        "AWS"
    );
    let generate =
        |call: KmsCallContext, key: &str, encryption_context: BTreeMap<String, String>| {
            service.generate_data_key_internal(KmsGenerateDataKeyRequest {
                call,
                key_id: key.into(),
                number_of_bytes: 32,
                encryption_context,
            })
        };
    let managed_data = generate(caller.clone(), "alias/aws/s3", context.clone()).unwrap();
    assert_eq!(managed_data.key_id, managed.key_arn);
    let decrypt_managed = |encryption_context| {
        service.decrypt_internal(KmsDecryptRequest {
            call: caller.clone(),
            key_id: Some(managed.key_arn.clone()),
            ciphertext: SensitiveBytes::new(managed_data.ciphertext.as_slice().to_vec()),
            encryption_context,
        })
    };
    assert_eq!(
        decrypt_managed(context.clone())
            .unwrap()
            .plaintext
            .as_slice(),
        managed_data.plaintext.as_slice()
    );
    assert!(matches!(
        decrypt_managed(BTreeMap::from([(
            "aws:s3:arn".into(),
            "arn:aws:s3:::orders/Other.pdf".into()
        )])),
        Err(KmsError::InvalidCiphertext)
    ));

    assert!(matches!(
        generate(
            KmsCallContext {
                iam_policy_denied: true,
                ..caller.clone()
            },
            "alias/aws/s3",
            context.clone()
        ),
        Err(KmsError::AccessDenied)
    ));
    assert!(matches!(
        generate(
            KmsCallContext {
                source_service: "ssm".into(),
                ..caller.clone()
            },
            &managed.key_arn,
            context.clone()
        ),
        Err(KmsError::AccessDenied)
    ));
    assert!(matches!(
        generate(
            KmsCallContext {
                caller_arn: Some("arn:aws:iam::111111111111:user/alice".into()),
                ..caller.clone()
            },
            &managed.key_arn,
            context.clone()
        ),
        Err(KmsError::AccessDenied)
    ));
    let (customer, customer_arn) = create_key(&service, ACCOUNT, REGION);
    assert!(matches!(
        generate(caller.clone(), &customer, context.clone()),
        Err(KmsError::AccessDenied)
    ));
    assert!(generate(
        KmsCallContext {
            iam_policy_allowed: true,
            ..caller.clone()
        },
        &customer,
        context.clone()
    )
    .is_ok());
    let policy = json!({"Statement":[
        {"Effect":"Allow","Principal":{"AWS":format!("arn:aws:iam::{ACCOUNT}:root")},"Action":"kms:*","Resource":"*"},
        {"Effect":"Allow","Principal":{"AWS":user},"Action":["kms:GenerateDataKey","kms:Decrypt"],"Resource":"*",
            "Condition":{"StringEquals":{"kms:ViaService":format!("s3.{REGION}.amazonaws.com"),"kms:CallerAccount":ACCOUNT},
                "StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::orders/Invoice*"}}}
    ]}).to_string();
    call_ok(
        &service,
        "PutKeyPolicy",
        json!({"KeyId":customer,"Policy":policy}),
    );
    let data = generate(caller.clone(), &customer, context.clone()).unwrap();
    assert!(matches!(
        generate(caller.clone(), &customer, BTreeMap::new()),
        Err(KmsError::AccessDenied)
    ));
    assert!(matches!(
        generate(
            caller.clone(),
            &customer,
            BTreeMap::from([("aws:s3:arn".into(), object.replace("Invoice", "invoice"))])
        ),
        Err(KmsError::AccessDenied)
    ));
    assert!(matches!(
        generate(
            KmsCallContext {
                iam_policy_denied: true,
                ..caller.clone()
            },
            &customer,
            context.clone()
        ),
        Err(KmsError::AccessDenied)
    ));
    assert!(generate(
        KmsCallContext {
            region: "us-west-2".into(),
            ..caller.clone()
        },
        &customer_arn,
        context.clone()
    )
    .is_err());
    let decrypt = |call: KmsCallContext, encryption_context| {
        service.decrypt_internal(KmsDecryptRequest {
            call,
            key_id: Some(customer_arn.clone()),
            ciphertext: SensitiveBytes::new(data.ciphertext.as_slice().to_vec()),
            encryption_context,
        })
    };
    assert_eq!(
        decrypt(caller.clone(), context.clone())
            .unwrap()
            .plaintext
            .as_slice(),
        data.plaintext.as_slice()
    );
    assert!(matches!(
        decrypt(caller.clone(), BTreeMap::new()),
        Err(KmsError::AccessDenied)
    ));
    call_ok(
        &service,
        "PutKeyPolicy",
        json!({"KeyId":customer,"Policy":KeyPolicy::default_for(ACCOUNT).raw()}),
    );
    assert!(matches!(
        decrypt(caller.clone(), context.clone()),
        Err(KmsError::AccessDenied)
    ));
    call_ok(
        &service,
        "ScheduleKeyDeletion",
        json!({"KeyId":customer,"PendingWindowInDays":7}),
    );
    assert!(matches!(
        decrypt(caller, context),
        Err(KmsError::InvalidState)
    ));
}

#[test]
fn customer_key_disable_survives_reopen_and_blocks_crypto_until_enabled() {
    let db = crate::test_db();
    let service = KmsService::new(db.clone()).unwrap();
    let (key, arn) = create_key(&service, ACCOUNT, REGION);
    let ciphertext = call_ok(
        &service,
        "Encrypt",
        json!({"KeyId":key,"Plaintext":STANDARD.encode(b"durable secret")}),
    )["CiphertextBlob"]
        .clone();
    call_ok(&service, "DisableKey", json!({"KeyId": arn}));
    assert!(matches!(
        service.validate_key_internal(KmsValidateKeyRequest {
            call: internal_call(ACCOUNT, REGION),
            key_id: key.clone(),
        }),
        Err(KmsError::Disabled)
    ));
    drop(service);
    let service = KmsService::new(db).unwrap();
    assert_eq!(
        call_ok(&service, "DescribeKey", json!({"KeyId": key}))["KeyMetadata"]["KeyState"],
        "Disabled"
    );
    assert!(matches!(
        call(
            &service,
            "GenerateDataKey",
            json!({"KeyId": key, "KeySpec":"AES_256"}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::Disabled)
    ));
    assert!(matches!(
        call(
            &service,
            "Decrypt",
            json!({"CiphertextBlob":ciphertext}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::Disabled)
    ));
    assert!(matches!(
        call(
            &service,
            "Encrypt",
            json!({"KeyId":key,"Plaintext":STANDARD.encode(b"durable secret")}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::Disabled)
    ));
    assert!(matches!(
        call(
            &service,
            "DisableKey",
            json!({"KeyId":arn}),
            ACCOUNT,
            "eu-west-1"
        ),
        Err(KmsError::NotFound)
    ));
    call_ok(&service, "EnableKey", json!({"KeyId": key}));
    assert_eq!(
        call_ok(&service, "Decrypt", json!({"CiphertextBlob":ciphertext}))["Plaintext"],
        STANDARD.encode(b"durable secret")
    );
    call_ok(
        &service,
        "GenerateDataKey",
        json!({"KeyId": key, "KeySpec":"AES_256"}),
    );
    let managed = service
        .service_default_key(&Scope::new(ACCOUNT, REGION), "s3")
        .unwrap();
    assert!(matches!(
        call(
            &service,
            "DisableKey",
            json!({"KeyId": managed}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::AccessDenied)
    ));
    call_ok(&service, "DisableKey", json!({"KeyId": key}));
    assert!(matches!(
        crate::map_internal_error(KmsError::Disabled),
        locallycloud_core::integration::kms::KmsInternalError::Disabled
    ));
    call_ok(&service, "ScheduleKeyDeletion", json!({"KeyId": key}));
    assert!(matches!(
        call(
            &service,
            "ScheduleKeyDeletion",
            json!({"KeyId":key}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::InvalidState)
    ));

    assert!(matches!(
        call(
            &service,
            "EnableKey",
            json!({"KeyId": key}),
            ACCOUNT,
            REGION
        ),
        Err(KmsError::InvalidState)
    ));
}
