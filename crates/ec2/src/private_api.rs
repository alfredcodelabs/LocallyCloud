//! TLS ingress shared by isolated compute guests targeting a modeled execute-api ENI.
use std::{
    io,
    net::SocketAddrV4,
    sync::{Arc, Weak},
};

use crate::{Ec2Handler, TaskNetworkLease};
use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request},
    routing::any,
    Router,
};
use locallycloud_core::{
    error_mapping::AwsError,
    handler::PrivateApiIngress,
    registry::{AwsProtocol, ServiceRegistry},
    tls::{ConnectionInfo, GuestCallbackTls},
};
use tokio::net::TcpStream;

/// No endpoint sockets or workers are created at registration; the guest owns this transport.
#[derive(Clone)]
pub struct PrivateApiTransport {
    ec2: Arc<Ec2Handler>,
    source: Arc<TaskNetworkLease>,
    account: String,
    region: String,
    registry: Weak<ServiceRegistry>,
    tls: Arc<GuestCallbackTls>,
}

impl PrivateApiTransport {
    pub fn new(
        ec2: Arc<Ec2Handler>,
        source: Arc<TaskNetworkLease>,
        scope: (String, String),
        registry: Weak<ServiceRegistry>,
        tls: Arc<GuestCallbackTls>,
    ) -> Self {
        Self {
            ec2,
            source,
            account: scope.0,
            region: scope.1,
            registry,
            tls,
        }
    }

    fn ingress(&self, destination: SocketAddrV4) -> Option<PrivateApiIngress> {
        let endpoint = self.ec2.interface_endpoint_access(
            &self.account,
            &self.region,
            &self.source,
            *destination.ip(),
            destination.port(),
        )?;
        if endpoint.service != "execute-api" {
            return None;
        }
        Some(PrivateApiIngress {
            endpoint_account: endpoint.endpoint_account,
            endpoint_region: endpoint.endpoint_region,
            vpc_id: endpoint.vpc_id,
            vpce_id: endpoint.endpoint_id,
            original_source_ip: endpoint.source_private_ip.into(),
            endpoint_ip: (*destination.ip()).into(),
            secure_transport: true,
            endpoint_policy: endpoint.policy_document,
        })
    }

    pub fn permits(&self, destination: SocketAddrV4) -> bool {
        self.ingress(destination).is_some()
    }

    pub async fn serve(&self, stream: TcpStream, destination: SocketAddrV4) -> io::Result<()> {
        if !self.permits(destination) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let resolver = self.tls.for_execute_api_region(&self.region).await?;
        let transport = self.clone();
        let app = Router::new().fallback(any(move |request: Request| {
            let transport = transport.clone();
            async move {
                let forbidden = || {
                    AwsError::new("ForbiddenException", "Forbidden", 403)
                        .render(AwsProtocol::RestJson)
                        .into_response()
                };
                let (parts, body) = request.into_parts();
                let Some(ConnectInfo(connection)) =
                    parts.extensions.get::<ConnectInfo<ConnectionInfo>>()
                else {
                    return forbidden();
                };
                if !connection.secure_transport {
                    return forbidden();
                }
                let body = match to_bytes(body, 10 * 1024 * 1024).await {
                    Ok(body) => body,
                    Err(_) => {
                        return AwsError::new(
                            "RequestTooLargeException",
                            "Request body too large",
                            413,
                        )
                        .render(AwsProtocol::RestJson)
                        .into_response()
                    }
                };
                // Re-read ownership, route, both SGs and the current policy on every request.
                let Some(ingress) = transport.ingress(destination) else {
                    return forbidden();
                };
                let Some(dispatcher) = transport
                    .registry
                    .upgrade()
                    .and_then(|r| r.internal_dispatcher())
                else {
                    return forbidden();
                };
                dispatcher
                    .dispatch_private_api(
                        &parts.method,
                        &parts.uri,
                        &parts.headers,
                        body,
                        &locallycloud_core::observability::new_request_id(),
                        ingress,
                    )
                    .await
            }
        }));
        GuestCallbackTls::serve_connection(stream, app, resolver).await
    }
}
