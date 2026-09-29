use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::AwsProtocol;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::crypto::{opaque_token, PasswordHash, SigningKey};
use crate::{CognitoError, TARGET_PREFIX};

const MAX_BODY: usize = 128 * 1024;
const TOKEN_LIFETIME: i64 = 3600;

#[derive(Clone, Eq, Hash, PartialEq)]
struct PoolScope {
    account: String,
    region: String,
    id: String,
}

struct AppClient {
    id: String,
    name: String,
    admin_password_auth: bool,
    created: i64,
}

struct User {
    username: String,
    sub: String,
    status: &'static str,
    enabled: bool,
    password: PasswordHash,
    attributes: BTreeMap<String, String>,
    created: i64,
}

struct Pool {
    id: String,
    arn: String,
    name: String,
    region: String,
    created: i64,
    clients: HashMap<String, AppClient>,
    users: HashMap<String, User>,
    access_key: SigningKey,
    id_key: SigningKey,
}

#[derive(Default)]
pub struct CognitoHandler {
    pools: RwLock<HashMap<PoolScope, Arc<Mutex<Pool>>>>,
}

impl CognitoHandler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Public-only JWKS snapshot for an issuer path. Does not expose the pool store or keys.
    pub fn jwks_for_pool(&self, account: &str, region: &str, pool_id: &str) -> Option<Value> {
        let scope = PoolScope {
            account: account.to_owned(),
            region: region.to_owned(),
            id: pool_id.to_owned(),
        };
        let pool = self.pools.read().ok()?.get(&scope)?.clone();
        let pool = pool.lock().ok()?;
        Some(json!({"keys": [pool.access_key.jwk(), pool.id_key.jwk()]}))
    }

    fn pool(&self, request: &ServiceRequest, id: &str) -> Result<Arc<Mutex<Pool>>, CognitoError> {
        if !id.starts_with(&format!("{}_", request.region)) {
            return Err(CognitoError::ResourceNotFound);
        }
        self.pools
            .read()
            .map_err(|_| CognitoError::Internal)?
            .get(&PoolScope {
                account: request.account_id.clone(),
                region: request.region.clone(),
                id: id.to_owned(),
            })
            .cloned()
            .ok_or(CognitoError::ResourceNotFound)
    }

    async fn process(&self, request: &ServiceRequest) -> Result<Value, CognitoError> {
        if request.method != http::Method::POST
            || request.uri.path() != "/"
            || request.uri.query().is_some()
        {
            return Err(CognitoError::UnknownOperation);
        }
        if request.body.len() > MAX_BODY {
            return Err(CognitoError::InvalidParameter);
        }
        let content_type = request
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with("application/x-amz-json-1.1")
            && !content_type.starts_with("application/x-amz-json-1.0")
        {
            return Err(CognitoError::InvalidParameter);
        }
        let operation = request
            .headers
            .get("x-amz-target")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix(&format!("{TARGET_PREFIX}.")))
            .filter(|value| !value.is_empty() && !value.contains('.'))
            .ok_or(CognitoError::UnknownOperation)?;
        let body: Value =
            serde_json::from_slice(&request.body).map_err(|_| CognitoError::InvalidParameter)?;
        let input = body.as_object().ok_or(CognitoError::InvalidParameter)?;
        match operation {
            "CreateUserPool" => self.create_pool(request, input).await,
            "DescribeUserPool" => self.describe_pool(request, input),
            "ListUserPools" => self.list_pools(request, input),
            "DeleteUserPool" => self.delete_pool(request, input),
            "CreateUserPoolClient" => self.create_client(request, input),
            "DescribeUserPoolClient" => self.describe_client(request, input),
            "ListUserPoolClients" => self.list_clients(request, input),
            "DeleteUserPoolClient" => self.delete_client(request, input),
            "AdminCreateUser" => self.admin_create_user(request, input),
            "AdminSetUserPassword" => self.admin_set_password(request, input),
            "AdminGetUser" => self.admin_get_user(request, input),
            "ListUsers" => self.list_users(request, input),
            "AdminDeleteUser" => self.admin_delete_user(request, input),
            "AdminInitiateAuth" => self.admin_auth(request, input),
            _ => Err(CognitoError::UnknownOperation),
        }
    }

    async fn create_pool(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["PoolName"])?;
        let name = string(input, "PoolName")?;
        if name.is_empty() || name.len() > 128 {
            return Err(CognitoError::InvalidParameter);
        }
        let id = format!(
            "{}_{}",
            request.region,
            &Uuid::new_v4().simple().to_string()[..9]
        );
        let arn = format!(
            "arn:aws:cognito-idp:{}:{}:userpool/{id}",
            request.region, request.account_id
        );
        let created = now()?;
        let (access_key, id_key) = tokio::task::spawn_blocking(|| {
            Ok::<_, CognitoError>((SigningKey::generate()?, SigningKey::generate()?))
        })
        .await
        .map_err(|_| CognitoError::Internal)??;
        let pool = Pool {
            id: id.clone(),
            arn,
            name: name.to_owned(),
            region: request.region.clone(),
            created,
            clients: HashMap::new(),
            users: HashMap::new(),
            access_key,
            id_key,
        };
        let result = pool_view(&pool);
        self.pools
            .write()
            .map_err(|_| CognitoError::Internal)?
            .insert(
                PoolScope {
                    account: request.account_id.clone(),
                    region: request.region.clone(),
                    id,
                },
                Arc::new(Mutex::new(pool)),
            );
        Ok(json!({"UserPool": result}))
    }

    fn describe_pool(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId"])?;
        let pool = self.pool(request, string(input, "UserPoolId")?)?;
        let pool = pool.lock().map_err(|_| CognitoError::Internal)?;
        Ok(json!({"UserPool": pool_view(&pool)}))
    }

    fn list_pools(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["MaxResults", "NextToken"])?;
        let max = positive_limit(input, "MaxResults", 60)?;
        let offset = page_offset(input)?;
        let pools = self.pools.read().map_err(|_| CognitoError::Internal)?;
        let mut values: Vec<_> = pools.iter().filter(|(scope, _)| scope.account == request.account_id && scope.region == request.region)
            .map(|(_, cell)| {
                let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
                Ok(json!({"Id": pool.id, "Name": pool.name, "LambdaConfig": {}, "Status": "Enabled", "CreationDate": pool.created, "LastModifiedDate": pool.created}))
            }).collect::<Result<_, CognitoError>>()?;
        values.sort_by(|a: &Value, b: &Value| a["Id"].as_str().cmp(&b["Id"].as_str()));
        page(values, offset, max, "UserPools")
    }

    fn delete_pool(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId"])?;
        let id = string(input, "UserPoolId")?;
        let key = PoolScope {
            account: request.account_id.clone(),
            region: request.region.clone(),
            id: id.to_owned(),
        };
        if self
            .pools
            .write()
            .map_err(|_| CognitoError::Internal)?
            .remove(&key)
            .is_none()
        {
            return Err(CognitoError::ResourceNotFound);
        }
        Ok(json!({}))
    }

    fn create_client(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            &[
                "UserPoolId",
                "ClientName",
                "ExplicitAuthFlows",
                "GenerateSecret",
            ],
        )?;
        let pool_id = string(input, "UserPoolId")?;
        let name = string(input, "ClientName")?;
        if name.is_empty()
            || name.len() > 128
            || input.get("GenerateSecret").and_then(Value::as_bool) == Some(true)
        {
            return Err(CognitoError::Unsupported);
        }
        let flows = input.get("ExplicitAuthFlows").and_then(Value::as_array);
        if let Some(flows) = flows {
            if flows.iter().any(|flow| {
                !matches!(
                    flow.as_str(),
                    Some("ALLOW_ADMIN_USER_PASSWORD_AUTH" | "ALLOW_REFRESH_TOKEN_AUTH")
                )
            }) {
                return Err(CognitoError::Unsupported);
            }
        }
        let admin_password_auth = flows.is_some_and(|flows| {
            flows
                .iter()
                .any(|flow| flow.as_str() == Some("ALLOW_ADMIN_USER_PASSWORD_AUTH"))
        });
        let cell = self.pool(request, pool_id)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let client = AppClient {
            id: Uuid::new_v4().simple().to_string(),
            name: name.to_owned(),
            admin_password_auth,
            created: now()?,
        };
        let result = client_view(&client, pool_id);
        pool.clients.insert(client.id.clone(), client);
        Ok(json!({"UserPoolClient": result}))
    }

    fn describe_client(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "ClientId"])?;
        let pool_id = string(input, "UserPoolId")?;
        let cell = self.pool(request, pool_id)?;
        let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let client = pool
            .clients
            .get(string(input, "ClientId")?)
            .ok_or(CognitoError::ResourceNotFound)?;
        Ok(json!({"UserPoolClient": client_view(client, pool_id)}))
    }

    fn list_clients(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "MaxResults", "NextToken"])?;
        let pool_id = string(input, "UserPoolId")?;
        let max = positive_limit(input, "MaxResults", 60)?;
        let offset = page_offset(input)?;
        let cell = self.pool(request, pool_id)?;
        let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let mut values: Vec<_> = pool.clients.values().map(|client| json!({"ClientId": client.id, "ClientName": client.name, "UserPoolId": pool_id})).collect();
        values.sort_by(|a, b| a["ClientId"].as_str().cmp(&b["ClientId"].as_str()));
        page(values, offset, max, "UserPoolClients")
    }

    fn delete_client(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "ClientId"])?;
        let cell = self.pool(request, string(input, "UserPoolId")?)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.clients.remove(string(input, "ClientId")?).is_none() {
            return Err(CognitoError::ResourceNotFound);
        }
        Ok(json!({}))
    }

    fn admin_create_user(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            &[
                "UserPoolId",
                "Username",
                "TemporaryPassword",
                "MessageAction",
                "UserAttributes",
            ],
        )?;
        let pool_id = string(input, "UserPoolId")?;
        let username = string(input, "Username")?;
        let password = string(input, "TemporaryPassword")?;
        if username.is_empty()
            || username.len() > 128
            || input.get("MessageAction").and_then(Value::as_str) != Some("SUPPRESS")
        {
            return Err(CognitoError::Unsupported);
        }
        validate_password(password)?;
        let attrs = attributes(input.get("UserAttributes"))?;
        let cell = self.pool(request, pool_id)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.users.contains_key(username) {
            return Err(CognitoError::UsernameExists);
        }
        let user = User {
            username: username.to_owned(),
            sub: Uuid::new_v4().to_string(),
            status: "FORCE_CHANGE_PASSWORD",
            enabled: true,
            password: PasswordHash::new(password),
            attributes: attrs,
            created: now()?,
        };
        let result = user_view(&user);
        pool.users.insert(username.to_owned(), user);
        Ok(json!({"User": result}))
    }

    fn admin_set_password(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "Username", "Password", "Permanent"])?;
        let pool_id = string(input, "UserPoolId")?;
        let username = string(input, "Username")?;
        let password = string(input, "Password")?;
        validate_password(password)?;
        let permanent = input
            .get("Permanent")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let cell = self.pool(request, pool_id)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let user = pool
            .users
            .get_mut(username)
            .ok_or(CognitoError::UserNotFound)?;
        user.password = PasswordHash::new(password);
        user.status = if permanent {
            "CONFIRMED"
        } else {
            "FORCE_CHANGE_PASSWORD"
        };
        Ok(json!({}))
    }

    fn admin_get_user(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "Username"])?;
        let cell = self.pool(request, string(input, "UserPoolId")?)?;
        let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let user = pool
            .users
            .get(string(input, "Username")?)
            .ok_or(CognitoError::UserNotFound)?;
        Ok(user_view(user))
    }

    fn list_users(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "Limit", "PaginationToken"])?;
        let max = positive_limit(input, "Limit", 60)?;
        let offset = input
            .get("PaginationToken")
            .and_then(Value::as_str)
            .map(|s| {
                s.parse::<usize>()
                    .map_err(|_| CognitoError::InvalidParameter)
            })
            .transpose()?
            .unwrap_or(0);
        let cell = self.pool(request, string(input, "UserPoolId")?)?;
        let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let mut values: Vec<_> = pool.users.values().map(user_view).collect();
        values.sort_by(|a, b| a["Username"].as_str().cmp(&b["Username"].as_str()));
        let end = offset.saturating_add(max).min(values.len());
        if offset > values.len() {
            return Err(CognitoError::InvalidParameter);
        }
        let mut result = json!({"Users": &values[offset..end]});
        if end < values.len() {
            result["PaginationToken"] = end.to_string().into();
        }
        Ok(result)
    }

    fn admin_delete_user(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(input, &["UserPoolId", "Username"])?;
        let cell = self.pool(request, string(input, "UserPoolId")?)?;
        let mut pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        if pool.users.remove(string(input, "Username")?).is_none() {
            return Err(CognitoError::UserNotFound);
        }
        Ok(json!({}))
    }

    fn admin_auth(
        &self,
        request: &ServiceRequest,
        input: &Map<String, Value>,
    ) -> Result<Value, CognitoError> {
        allowed(
            input,
            &["UserPoolId", "ClientId", "AuthFlow", "AuthParameters"],
        )?;
        if string(input, "AuthFlow")? != "ADMIN_USER_PASSWORD_AUTH" {
            return Err(CognitoError::Unsupported);
        }
        let pool_id = string(input, "UserPoolId")?;
        let client_id = string(input, "ClientId")?;
        let params = input
            .get("AuthParameters")
            .and_then(Value::as_object)
            .ok_or(CognitoError::InvalidParameter)?;
        allowed(params, &["USERNAME", "PASSWORD"])?;
        let username = string(params, "USERNAME")?;
        let password = string(params, "PASSWORD")?;
        let cell = self.pool(request, pool_id)?;
        let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
        let client = pool
            .clients
            .get(client_id)
            .ok_or(CognitoError::ResourceNotFound)?;
        if !client.admin_password_auth {
            return Err(CognitoError::NotAuthorized);
        }
        let user = pool
            .users
            .get(username)
            .ok_or(CognitoError::NotAuthorized)?;
        if !user.enabled || user.status != "CONFIRMED" || !user.password.verify(password) {
            return Err(CognitoError::NotAuthorized);
        }
        let issued = now()?;
        let issuer = issuer(&pool);
        let access = json!({
            "sub": user.sub, "iss": issuer, "client_id": client_id, "token_use": "access",
            "auth_time": issued, "iat": issued, "exp": issued + TOKEN_LIFETIME,
            "jti": Uuid::new_v4().to_string(), "username": username,
            "scope": "aws.cognito.signin.user.admin"
        });
        let mut id = json!({
            "sub": user.sub, "iss": issuer, "aud": client_id, "token_use": "id",
            "auth_time": issued, "iat": issued, "exp": issued + TOKEN_LIFETIME,
            "jti": Uuid::new_v4().to_string(), "cognito:username": username
        });
        for key in [
            "email",
            "name",
            "phone_number",
            "email_verified",
            "phone_number_verified",
        ] {
            if let Some(value) = user.attributes.get(key) {
                id[key] = value.clone().into();
            }
        }
        Ok(json!({"AuthenticationResult": {
            "AccessToken": pool.access_key.sign(&access)?,
            "IdToken": pool.id_key.sign(&id)?,
            "RefreshToken": opaque_token(),
            "ExpiresIn": TOKEN_LIFETIME,
            "TokenType": "Bearer"
        }}))
    }

    fn public_metadata_response(&self, request: &ServiceRequest) -> Result<Value, CognitoError> {
        let components: Vec<_> = request.uri.path().split('/').collect();
        if components.len() != 4 || !components[0].is_empty() || components[2] != ".well-known" {
            return Err(CognitoError::ResourceNotFound);
        }
        let pool_id = components[1];
        match components[3] {
            "jwks.json" => self
                .jwks_for_pool(&request.account_id, &request.region, pool_id)
                .ok_or(CognitoError::ResourceNotFound),
            "openid-configuration" => {
                let cell = self.pool(request, pool_id)?;
                let pool = cell.lock().map_err(|_| CognitoError::Internal)?;
                let issuer = issuer(&pool);
                Ok(json!({
                    "issuer": issuer,
                    "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "subject_types_supported": ["public"]
                }))
            }
            _ => Err(CognitoError::ResourceNotFound),
        }
    }
}

#[async_trait]
impl NativeHandler for CognitoHandler {
    async fn handle(&self, request: ServiceRequest) -> Response {
        let result = if request.method == http::Method::GET {
            self.public_metadata_response(&request)
        } else {
            self.process(&request).await
        };
        match result {
            Ok(value) => Response::builder()
                .status(http::StatusCode::OK)
                .header(
                    http::header::CONTENT_TYPE,
                    if request.method == http::Method::GET {
                        "application/json"
                    } else {
                        "application/x-amz-json-1.1"
                    },
                )
                .header("x-amzn-RequestId", &request.request_id)
                .body(Body::from(value.to_string()))
                .expect("valid Cognito response"),
            Err(error) => error
                .into_aws()
                .with_request_id(request.request_id)
                .render(AwsProtocol::Json11)
                .into_response(),
        }
    }
}

fn string<'a>(input: &'a Map<String, Value>, name: &str) -> Result<&'a str, CognitoError> {
    input
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(CognitoError::InvalidParameter)
}

fn allowed(input: &Map<String, Value>, names: &[&str]) -> Result<(), CognitoError> {
    if input.keys().all(|key| names.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(CognitoError::Unsupported)
    }
}

fn positive_limit(
    input: &Map<String, Value>,
    name: &str,
    max: usize,
) -> Result<usize, CognitoError> {
    let value = input
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(CognitoError::InvalidParameter)? as usize;
    if value == 0 || value > max {
        Err(CognitoError::InvalidParameter)
    } else {
        Ok(value)
    }
}

fn page_offset(input: &Map<String, Value>) -> Result<usize, CognitoError> {
    input
        .get("NextToken")
        .and_then(Value::as_str)
        .map(|s| s.parse().map_err(|_| CognitoError::InvalidParameter))
        .transpose()
        .map(|v| v.unwrap_or(0))
}

fn page(values: Vec<Value>, offset: usize, max: usize, key: &str) -> Result<Value, CognitoError> {
    if offset > values.len() {
        return Err(CognitoError::InvalidParameter);
    }
    let end = offset.saturating_add(max).min(values.len());
    let mut result = json!({key: &values[offset..end]});
    if end < values.len() {
        result["NextToken"] = end.to_string().into();
    }
    Ok(result)
}

fn attributes(value: Option<&Value>) -> Result<BTreeMap<String, String>, CognitoError> {
    let mut result = BTreeMap::new();
    if let Some(value) = value {
        let values = value.as_array().ok_or(CognitoError::InvalidParameter)?;
        for item in values {
            let item = item.as_object().ok_or(CognitoError::InvalidParameter)?;
            allowed(item, &["Name", "Value"])?;
            let name = string(item, "Name")?;
            let value = string(item, "Value")?;
            if name == "sub" || result.insert(name.to_owned(), value.to_owned()).is_some() {
                return Err(CognitoError::InvalidParameter);
            }
        }
    }
    Ok(result)
}

fn validate_password(password: &str) -> Result<(), CognitoError> {
    if password.len() < 8
        || password.len() > 256
        || password.chars().any(char::is_whitespace)
        || !password.chars().any(char::is_uppercase)
        || !password.chars().any(char::is_lowercase)
        || !password.chars().any(|c| c.is_ascii_digit())
        || !password.chars().any(|c| !c.is_alphanumeric())
    {
        Err(CognitoError::InvalidPassword)
    } else {
        Ok(())
    }
}

fn now() -> Result<i64, CognitoError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CognitoError::Internal)?
        .as_secs() as i64)
}

fn issuer(pool: &Pool) -> String {
    format!(
        "https://cognito-idp.{}.amazonaws.com/{}",
        pool.region, pool.id
    )
}

fn pool_view(pool: &Pool) -> Value {
    json!({
        "Id": pool.id, "Name": pool.name, "Arn": pool.arn,
        "Status": "Enabled", "CreationDate": pool.created,
        "LastModifiedDate": pool.created, "EstimatedNumberOfUsers": pool.users.len(),
        "Policies": {"PasswordPolicy": {"MinimumLength": 8, "RequireUppercase": true, "RequireLowercase": true, "RequireNumbers": true, "RequireSymbols": true}},
        "LambdaConfig": {}
    })
}

fn client_view(client: &AppClient, pool_id: &str) -> Value {
    json!({
        "ClientId": client.id, "ClientName": client.name, "UserPoolId": pool_id,
        "CreationDate": client.created, "LastModifiedDate": client.created,
        "ExplicitAuthFlows": if client.admin_password_auth { vec!["ALLOW_ADMIN_USER_PASSWORD_AUTH"] } else { vec!["ALLOW_USER_SRP_AUTH", "ALLOW_CUSTOM_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"] },
        "AccessTokenValidity": 60, "IdTokenValidity": 60,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes"}
    })
}

fn user_view(user: &User) -> Value {
    let mut attrs = vec![json!({"Name": "sub", "Value": user.sub})];
    attrs.extend(
        user.attributes
            .iter()
            .map(|(name, value)| json!({"Name": name, "Value": value})),
    );
    json!({
        "Username": user.username, "UserAttributes": attrs,
        "UserCreateDate": user.created, "UserLastModifiedDate": user.created,
        "Enabled": user.enabled, "UserStatus": user.status
    })
}
