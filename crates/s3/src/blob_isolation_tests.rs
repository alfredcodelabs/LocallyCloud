//! Public HTTP regression for independent state databases with matching filename stems.
use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method};
use locallycloud_core::{
    config::LocallyCloudConfig,
    registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry},
    server::LocallyCloudServer,
};
use locallycloud_state::StateDb;

struct Server {
    endpoint: String,
    client: reqwest::Client,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    _state_lock: std::fs::File,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Server {
    async fn start(path: &Path) -> Self {
        let state = Arc::new(StateDb::open(path.to_owned()).unwrap());
        let state_lock = state.lock_runtime().unwrap();
        let registry = ServiceRegistry::with_known_services();
        let keys = crate::encryption::StorageKeys::with_master(&state, &[0x42; 32]).unwrap();
        let handler =
            super::S3Handler::with_storage_keys(Arc::downgrade(&registry), state, keys).unwrap();
        registry.register_native(
            ServiceName::new("s3"),
            ServiceMetadata::new(AwsProtocol::RestXml, None),
            Arc::new(handler),
        );
        let config = LocallyCloudConfig::resolve(&|name| match name {
            "LOCALLYCLOUD_UI" => Some("off".into()),
            "LOCALLYCLOUD_LEGACY_BACKEND_URL" => Some("http://127.0.0.1:1".into()),
            _ => None,
        })
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            LocallyCloudServer::new(config, registry)
                .run_on_listener(
                    listener,
                    async {
                        let _ = stopped.await;
                    },
                    move || {
                        let _ = ready.send(());
                    },
                )
                .await
                .unwrap();
        });
        started.await.unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=test/20261105/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000",
        ));
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            endpoint,
            client,
            stop: Some(stop),
            task,
            _state_lock: state_lock,
        }
    }

    async fn request(&self, method: Method, path: &str, body: Vec<u8>) -> (u16, HeaderMap, Bytes) {
        let response = self
            .client
            .request(method, format!("{}{path}", self.endpoint))
            .body(body)
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        (status, headers, response.bytes().await.unwrap())
    }

    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(10), &mut self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn encrypted_objects_survive_other_database_startup_deletion_and_restart_over_http() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let first_path = root.path().join("state.db");
    let second_path = root.path().join("state.sqlite3");
    // Exceed one encrypted chunk so ciphertext is persisted in blob files, not inline JSON.
    let first_body = vec![b'A'; crate::encryption::CHUNK + 1];
    let second_body = vec![b'B'; crate::encryption::CHUNK + 1];
    let first = Server::start(&first_path).await;
    assert_eq!(
        first
            .request(Method::PUT, "/isolation-bucket", Vec::new())
            .await
            .0,
        200
    );
    assert_eq!(
        first
            .request(Method::PUT, "/isolation-bucket/key", first_body.clone())
            .await
            .0,
        200
    );
    first.shutdown().await;

    let second = Server::start(&second_path).await;
    assert_eq!(
        second
            .request(Method::GET, "/isolation-bucket/key", Vec::new())
            .await
            .0,
        404
    );
    let first = Server::start(&first_path).await;
    let (status, headers, body) = first
        .request(Method::GET, "/isolation-bucket/key", Vec::new())
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers["x-amz-server-side-encryption"], "AES256");
    assert_eq!(body.as_ref(), first_body);
    assert_eq!(
        second
            .request(Method::PUT, "/isolation-bucket", Vec::new())
            .await
            .0,
        200
    );
    assert_eq!(
        second
            .request(Method::PUT, "/isolation-bucket/key", second_body.clone())
            .await
            .0,
        200
    );
    assert_eq!(
        first
            .request(Method::DELETE, "/isolation-bucket/key", Vec::new())
            .await
            .0,
        204
    );
    assert_eq!(
        first
            .request(Method::DELETE, "/isolation-bucket", Vec::new())
            .await
            .0,
        204
    );
    first.shutdown().await;
    second.shutdown().await;

    let first = Server::start(&first_path).await;
    let second = Server::start(&second_path).await;
    assert_eq!(
        first
            .request(Method::GET, "/isolation-bucket/key", Vec::new())
            .await
            .0,
        404
    );
    let (status, headers, body) = second
        .request(Method::GET, "/isolation-bucket/key", Vec::new())
        .await;
    assert_eq!(status, 200);
    assert_eq!(headers["x-amz-server-side-encryption"], "AES256");
    assert_eq!(body.as_ref(), second_body);
    first.shutdown().await;
    second.shutdown().await;
}
