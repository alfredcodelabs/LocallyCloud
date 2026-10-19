//! Owned ECS IPv4 transport. Only host-attested task leases select network policy.
use std::io;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use locallycloud_compute::youki::{original_tcp_destination, YoukiRuntime};
use locallycloud_ec2::{Ec2Handler, InstanceRuntime, PrivateTargetOwner, TaskNetworkLease};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::ecs_runtime::TaskConnector;

const MAX_CONNECTIONS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

pub struct NetworkEndpoints {
    workers: Vec<JoinHandle<()>>,
}

struct NetworkContext {
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    source: Arc<TaskNetworkLease>,
    tasks: TaskConnector,
    instances: Arc<dyn InstanceRuntime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Destination {
    Private {
        owner: PrivateTargetOwner,
        endpoint: std::net::SocketAddr,
    },
    Public(SocketAddrV4),
}

impl NetworkContext {
    fn destination(&self, destination: SocketAddrV4) -> Option<Destination> {
        if let Some(target) = self.ec2.private_connection_target(
            &self.account,
            &self.region,
            &self.source,
            *destination.ip(),
            destination.port(),
        ) {
            return Some(Destination::Private {
                owner: target.owner,
                endpoint: target.endpoint,
            });
        }
        self.ec2
            .public_tcp_access(
                &self.account,
                &self.region,
                &self.source.eni_id,
                *destination.ip(),
                destination.port(),
            )
            .then_some(Destination::Public(destination))
    }

    async fn connect(
        &self,
        address: SocketAddrV4,
        destination: &Destination,
    ) -> io::Result<TcpStream> {
        match destination {
            Destination::Private {
                owner: PrivateTargetOwner::Task(id),
                ..
            } => self.tasks.connect(id, *address.ip(), address.port()).await,
            Destination::Private {
                owner: PrivateTargetOwner::Instance(id),
                ..
            } => self
                .instances
                .connect_instance(id, address.port())
                .await
                .map_err(io::Error::other),
            Destination::Private {
                owner: PrivateTargetOwner::HostSocket,
                endpoint,
            } => TcpStream::connect(endpoint).await,
            Destination::Public(address) => TcpStream::connect(address).await,
        }
    }

    async fn forward(&self, mut guest: TcpStream, address: SocketAddrV4) {
        let Some(destination) = self.destination(address) else {
            return;
        };
        let Ok(Ok(mut backend)) =
            timeout(CONNECT_TIMEOUT, self.connect(address, &destination)).await
        else {
            return;
        };
        if self.destination(address).as_ref() != Some(&destination) {
            return;
        }
        let transfer = async {
            let copy = tokio::io::copy_bidirectional(&mut guest, &mut backend);
            tokio::pin!(copy);
            let mut policy_tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = &mut copy => break,
                    _ = policy_tick.tick() => {
                        if self.destination(address).as_ref() != Some(&destination) {
                            break;
                        }
                    }
                }
            }
        };
        let _ = timeout(CONNECTION_LIFETIME, transfer).await;
    }
}

impl NetworkEndpoints {
    pub async fn start(
        runtime: Arc<YoukiRuntime>,
        task_id: &str,
        ec2: Arc<Ec2Handler>,
        source: Arc<TaskNetworkLease>,
        scope: (String, String),
        tasks: TaskConnector,
        instances: Arc<dyn InstanceRuntime>,
    ) -> Result<Self, String> {
        let upstream = tokio::task::spawn_blocking(locallycloud_ec2::guest_dns::system_resolver)
            .await
            .map_err(|error| format!("Task DNS resolver worker failed: {error}"))?
            .map_err(|error| format!("Task DNS resolver is unavailable: {error}"))?;
        let (udp, tcp) = runtime
            .bind_isolated_dns(task_id)
            .await
            .map_err(|error| format!("Task DNS setup failed: {error}"))?;
        let listener = runtime
            .bind_isolated_vpc_egress(task_id)
            .await
            .map_err(|error| format!("Task VPC TCP setup failed: {error}"))?;
        let (account, region) = scope;
        let mut workers = locallycloud_ec2::guest_dns::serve(
            udp,
            tcp,
            upstream,
            ec2.clone(),
            account.clone(),
            region.clone(),
            source.eni_id.clone(),
        )
        .into_iter()
        .collect::<Vec<_>>();
        let context = Arc::new(NetworkContext {
            ec2,
            account,
            region,
            source,
            tasks,
            instances,
        });
        workers.push(tokio::spawn(serve_tcp(listener, context)));
        Ok(Self { workers })
    }

    pub async fn shutdown(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
        for worker in self.workers.drain(..) {
            let _ = worker.await;
        }
    }
}

impl Drop for NetworkEndpoints {
    fn drop(&mut self) {
        for worker in &self.workers {
            worker.abort();
        }
    }
}

async fn serve_tcp(listener: TcpListener, context: Arc<NetworkContext>) {
    // JoinSet owns accepted sockets: aborting the task also cancels every connection.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((guest, _)) = accepted else { break };
                if connections.len() >= MAX_CONNECTIONS {
                    continue;
                }
                let Ok(destination) = original_tcp_destination(&guest) else { continue };
                let context = context.clone();
                connections.spawn(async move { context.forward(guest, destination).await });
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}
