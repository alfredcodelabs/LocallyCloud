use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn policy_client(
    local_origins: &[String],
    listeners: &[SocketAddr],
) -> Result<EgressClient, String> {
    EgressClient::new(
        EgressSettings {
            local_origins: local_origins.to_vec(),
            ..Default::default()
        },
        listeners,
    )
}

fn origin(value: &str) -> Origin {
    Origin::parse(value).unwrap().0
}

#[test]
fn local_permissions_are_exact_origins_and_special_destinations_are_never_excepted() {
    let client = policy_client(&["http://127.0.0.1:8080".into()], &[]).unwrap();
    assert!(client
        .request(Method::GET, "http://127.0.0.1:8080/path?query=yes")
        .is_ok());
    for url in [
        "http://127.0.0.1:8081",
        "https://127.0.0.1:8080",
        "http://127.1:8081",
        "http://10.0.0.1",
        "http://100.64.0.1",
        "http://[fd01::1]",
        "http://user:secret@example.com",
        "http://example.com/#fragment",
        "file:///etc/passwd",
    ] {
        assert!(client.request(Method::GET, url).is_err(), "{url}");
    }
    for url in [
        "http://169.254.169.254",
        "http://100.100.100.200",
        "http://[fd00:ec2::254]",
        "http://[fd00:ec2::23]",
        "http://[fd00:ec2:ffff::1]",
        "http://192.88.99.1",
        "http://[2001:4860::5efe:a9fe:a9fe]",
        "http://[fd01::200:5efe:7f00:1]",
        "http://[::ffff:169.254.169.254]",
        "http://0.0.0.0",
        "http://224.0.0.1",
        "http://255.255.255.255",
        "http://[fe80::1]",
        "http://[ff02::1]",
        "http://[64:ff9b::a00:1]",
    ] {
        assert!(policy_client(&[url.into()], &[]).is_err(), "{url}");
    }
    for url in [
        "http://example.com/path",
        "http://example.com/?q=yes",
        "http://example.com/#fragment",
        "http://*.example.com",
        "http://api.*.example.com",
    ] {
        assert!(policy_client(&[url.into()], &[]).is_err(), "{url}");
    }
    assert_eq!(
        origin("http://EXAMPLE.com:80"),
        origin("http://example.com")
    );
    assert_eq!(origin("http://example.com."), origin("http://example.com"));
    assert_ne!(origin("http://example.com.."), origin("http://example.com"));
    assert!(client.request(Method::GET, "http://*.example.com").is_err());
    assert!(policy_client(&["http://[fd01::1]".into()], &[]).is_ok());
}

#[test]
fn self_listener_overrides_explicit_origin_permission() {
    assert!(policy_client(
        &["http://127.0.0.1:4566".into()],
        &["127.0.0.1:4566".parse().unwrap()]
    )
    .is_err());
    assert!(policy_client(
        &["http://127.0.0.2:4566".into()],
        &["0.0.0.0:4566".parse().unwrap()]
    )
    .is_err());
    assert!(policy_client(
        &["http://[::ffff:127.0.0.1]:4566".into()],
        &["127.0.0.1:4566".parse().unwrap()]
    )
    .is_err());
}

#[test]
fn public_host_addresses_require_explicit_permission_and_probe_errors_deny() {
    let origin = origin("http://public-backend.test:8080");
    let address = "8.8.8.8".parse().unwrap();
    let denied = Policy::new(&[], &[]).unwrap();
    assert!(denied
        .check_with_local(&origin, address, |_| Ok(true))
        .is_err());
    assert!(denied
        .check_with_local(&origin, address, |_| Ok(false))
        .is_ok());
    assert!(denied
        .check_with_local(&origin, address, |_| Err(EgressError::HostProbe))
        .is_err());
    let allowed = Policy::new(&["http://public-backend.test:8080".into()], &[]).unwrap();
    assert!(allowed
        .check_with_local(&origin, address, |_| panic!("unneeded host probe"))
        .is_ok());
    assert!(is_host_address("127.0.0.1".parse().unwrap()).unwrap());
}

struct Answers(Mutex<VecDeque<Vec<SocketAddr>>>);

impl Resolve for Answers {
    fn resolve(&self, _: Name) -> Resolving {
        let answer = self.0.lock().unwrap().pop_front().unwrap();
        Box::pin(async move { Ok(Box::new(answer.into_iter()) as Addrs) })
    }
}

#[tokio::test]
async fn resolver_checks_each_connection_and_rejects_mixed_answers() {
    let client = policy_client(&[], &[]).unwrap();
    let source = Arc::new(Answers(Mutex::new(VecDeque::from([
        vec!["1.1.1.1:0".parse().unwrap()],
        vec!["127.0.0.1:0".parse().unwrap()],
        vec!["1.1.1.1:0".parse().unwrap(), "10.0.0.1:0".parse().unwrap()],
    ]))));
    let resolver = FilteredResolver {
        origin: origin("https://backend.test:8443"),
        policy: client.policy,
        source,
    };
    let addresses: Vec<_> = resolver
        .resolve("backend.test".parse().unwrap())
        .await
        .unwrap()
        .collect();
    assert_eq!(addresses, ["1.1.1.1:8443".parse().unwrap()]);
    assert!(resolver
        .resolve("backend.test".parse().unwrap())
        .await
        .is_err());
    assert!(resolver
        .resolve("backend.test".parse().unwrap())
        .await
        .is_err());
}

async fn backend(response: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let size = socket.read(&mut request).await.unwrap();
        request.truncate(size);
        socket.write_all(response).await.unwrap();
        request
    });
    (address, server)
}

#[tokio::test]
async fn actual_connector_enforces_dns_and_literal_policy_without_following_redirects() {
    let (address, server) = backend(b"HTTP/1.1 302 Found\r\nLocation: /owned-redirect-target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
    let literal = format!("http://{address}");
    let denied = policy_client(&[], &[]).unwrap();
    assert!(denied.request(Method::GET, &literal).is_err());
    let hostname = format!("http://backend.test:{}", address.port());
    let mut client = policy_client(std::slice::from_ref(&hostname), &[]).unwrap();
    client.resolver = Arc::new(Answers(Mutex::new(VecDeque::from([vec![address]]))));
    let response = client
        .request(Method::GET, &hostname)
        .unwrap()
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let request = server.await.unwrap();
    assert!(String::from_utf8_lossy(&request)
        .contains(&format!("host: backend.test:{}", address.port())));
    let mut denied = policy_client(&[], &[]).unwrap();
    denied.resolver = Arc::new(Answers(Mutex::new(VecDeque::from([vec![address]]))));
    let error = denied
        .request(Method::GET, &hostname)
        .unwrap()
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        EgressError::from_request(&error),
        EgressError::DestinationDenied
    );
}

#[tokio::test]
async fn failed_dns_resolution_is_preserved_as_a_configuration_failure() {
    struct FailedDns;
    impl Resolve for FailedDns {
        fn resolve(&self, _: Name) -> Resolving {
            Box::pin(async { Err(std::io::Error::from(std::io::ErrorKind::NotFound).into()) })
        }
    }
    let mut client = policy_client(&[], &[]).unwrap();
    client.resolver = Arc::new(FailedDns);
    let error = client
        .request(Method::GET, "https://owned-dns-failure.test")
        .unwrap()
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap_err();
    let failure = EgressError::from_request(&error);
    assert_eq!(failure, EgressError::DnsResolution);
}

#[tokio::test]
async fn untrusted_tls_certificate_is_a_configuration_failure_without_sending_http() {
    use axum::{routing::get, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let identity = Arc::new(crate::tls::GuestCallbackTls::new().await.unwrap());
    let server = identity.clone().spawn(
        listener,
        Router::new().route(
            "/",
            get(move || {
                let observed = observed.clone();
                async move {
                    observed.fetch_add(1, Ordering::SeqCst);
                    "owned TLS backend"
                }
            }),
        ),
        false,
    );
    let trusted = Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(identity.ca_pem().as_bytes()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        trusted
            .get(&origin)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let client = policy_client(std::slice::from_ref(&origin), &[]).unwrap();
    let error = client
        .request(Method::GET, &origin)
        .unwrap()
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap_err();
    let failure = EgressError::from_request(&error);
    assert_eq!(failure, EgressError::TlsConfiguration);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    server.abort();
}

#[test]
fn client_cache_is_bounded_under_many_origins() {
    let client = EgressClient::new(
        EgressSettings {
            client_capacity: 2,
            ..Default::default()
        },
        &[],
    )
    .unwrap();
    for index in 0..6 {
        let _request = client
            .request(Method::GET, &format!("https://backend-{index}.example"))
            .unwrap();
    }
    assert_eq!(client.clients.lock().unwrap().len(), 2);
    assert!(EgressClient::new(
        EgressSettings {
            client_capacity: 0,
            ..Default::default()
        },
        &[]
    )
    .is_err());
}
