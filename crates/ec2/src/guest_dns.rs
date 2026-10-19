//! Bounded AmazonProvidedDNS relay owned by an isolated compute guest.
//! Upstream DNS uses only the host-configured resolver; application egress has separate policy.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::Ec2Handler;

const MAX_PACKET: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(3);
const CONNECTION_LIFETIME: Duration = Duration::from_secs(30);

/// Read static host configuration from a blocking setup context, never a packet worker.
pub fn system_resolver() -> io::Result<SocketAddr> {
    let config = std::fs::read_to_string("/etc/resolv.conf")?;
    config
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            (fields.next() == Some("nameserver"))
                .then(|| fields.next().and_then(|value| value.parse::<IpAddr>().ok()))
                .flatten()
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no system DNS nameserver"))
}

struct Question {
    name: String,
    kind: u16,
    class: u16,
    end: usize,
}

fn question(packet: &[u8]) -> Option<Question> {
    if !(17..=MAX_PACKET).contains(&packet.len())
        || packet[2] & 0xf8 != 0
        || packet[4..6] != [0, 1]
        || packet[6..10] != [0, 0, 0, 0]
    {
        return None;
    }
    let mut offset = 12usize;
    let mut name = String::new();
    loop {
        let length = usize::from(*packet.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        let label = packet.get(offset..offset.checked_add(length)?)?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'.')
        {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        if name.len() > 253 {
            return None;
        }
        offset += length;
    }
    let fields = packet.get(offset..offset.checked_add(4)?)?;
    Some(Question {
        name: name.to_ascii_lowercase(),
        kind: u16::from_be_bytes([fields[0], fields[1]]),
        class: u16::from_be_bytes([fields[2], fields[3]]),
        end: offset + 4,
    })
}

fn valid_reply(query: &[u8], reply: &[u8]) -> bool {
    // Echoed question prevents accepting a same-ID response for a different DNS request.
    let Some(query_question) = question(query) else {
        return false;
    };
    if !(query_question.end..=MAX_PACKET).contains(&reply.len())
        || reply[0..2] != query[0..2]
        || reply[2] & 0x80 == 0
        || reply[2] & 0x78 != 0
        || reply[4..6] != [0, 1]
    {
        return false;
    }
    reply.get(12..query_question.end) == query.get(12..query_question.end)
}

#[derive(Clone)]
struct Scope {
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    eni: String,
}
impl Scope {
    fn enabled(&self) -> bool {
        self.ec2
            .vpc_dns_enabled(&self.account, &self.region, &self.eni)
    }
    fn managed_reply(&self, query: &[u8]) -> Option<Vec<u8>> {
        let question = question(query)?;
        if question.class != 1 {
            return None;
        }
        let ip = self
            .ec2
            .private_tcp_dns(&self.account, &self.region, &self.eni)
            .into_iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&question.name))?
            .1;
        let mut reply = query.get(..question.end)?.to_vec();
        reply[2] = 0x80 | (query[2] & 0x01); // QR and the guest's recursion-desired bit.
        reply[3] = 0x80 | (query[3] & 0x10); // Recursion available; retain checking-disabled.
        reply[6..12].fill(0);
        if question.kind == 1 {
            reply[7] = 1;
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]); // TTL zero: never cache managed lease ownership.
            reply.extend_from_slice(&ip.octets());
        }
        Some(reply)
    }
}

async fn udp_reply(upstream: SocketAddr, query: &[u8]) -> io::Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    socket.send(query).await?;
    let mut reply = vec![0u8; MAX_PACKET + 1];
    let size = socket.recv(&mut reply).await?;
    reply.truncate(size);
    if !valid_reply(query, &reply) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(reply)
}

async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let size = usize::from(u16::from_be_bytes(length));
    if !(17..=MAX_PACKET).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut packet = vec![0u8; size];
    stream.read_exact(&mut packet).await?;
    Ok(packet)
}
async fn write_frame(stream: &mut TcpStream, packet: &[u8]) -> io::Result<()> {
    let length = u16::try_from(packet.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(packet).await
}
async fn tcp_guest(mut guest: TcpStream, upstream: SocketAddr, scope: Scope) -> io::Result<()> {
    loop {
        let query = timeout(TIMEOUT, read_frame(&mut guest)).await??;
        if !scope.enabled() || question(&query).is_none() {
            return Ok(());
        }
        timeout(TIMEOUT, async {
            let reply = if let Some(reply) = scope.managed_reply(&query) {
                reply
            } else {
                let mut resolver = TcpStream::connect(upstream).await?;
                write_frame(&mut resolver, &query).await?;
                let reply = read_frame(&mut resolver).await?;
                if !valid_reply(&query, &reply) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                reply
            };
            if scope.enabled() {
                write_frame(&mut guest, &reply).await?;
            }
            Ok::<_, io::Error>(())
        })
        .await??;
        if !scope.enabled() {
            return Ok(());
        }
    }
}

/// Start UDP/TCP listeners. Abort and await both returned handles when the guest stops.
/// Each parent owns all in-flight workers; aborting it drops their sockets and cancels I/O.
pub fn serve(
    udp: UdpSocket,
    tcp: TcpListener,
    upstream: SocketAddr,
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    eni: String,
) -> [JoinHandle<()>; 2] {
    let scope = Scope {
        ec2,
        account,
        region,
        eni,
    };
    let udp_scope = scope.clone();
    let udp = Arc::new(udp);
    let udp_task = tokio::spawn(async move {
        let mut workers = JoinSet::new();
        let mut packet = [0u8; MAX_PACKET + 1];
        loop {
            tokio::select! {
                _ = workers.join_next(), if !workers.is_empty() => {}
                received = udp.recv_from(&mut packet) => {
                    let Ok((size, peer)) = received else { break; };
                    if workers.len() >= 64 || !udp_scope.enabled() || question(&packet[..size]).is_none() { continue; }
                    let query = packet[..size].to_vec();
                    let udp = udp.clone();
                    let scope = udp_scope.clone();
                    workers.spawn(async move {
                        let _ = timeout(TIMEOUT, async {
                            let reply = if let Some(reply) = scope.managed_reply(&query) { reply }
                                else { udp_reply(upstream, &query).await? };
                            if scope.enabled() { udp.send_to(&reply, peer).await?; }
                            Ok::<_,io::Error>(())
                        }).await;
                    });
                }
            }
        }
    });
    let tcp_task = tokio::spawn(async move {
        let mut workers = JoinSet::new();
        loop {
            tokio::select! {
                _ = workers.join_next(), if !workers.is_empty() => {}
                accepted = tcp.accept() => {
                    let Ok((guest,_)) = accepted else { break; };
                    if workers.len() >= 32 || !scope.enabled() { continue; }
                    let scope = scope.clone();
                    workers.spawn(async move {
                        let _ = timeout(CONNECTION_LIFETIME, tcp_guest(guest, upstream, scope)).await;
                    });
                }
            }
        }
    });
    [udp_task, tcp_task]
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use locallycloud_core::handler::{NativeHandler, ServiceRequest};

    async fn call(ec2: &Ec2Handler, body: String) -> String {
        let response = ec2
            .handle(ServiceRequest {
                method: axum::http::Method::POST,
                uri: "/".parse().unwrap(),
                headers: Default::default(),
                body: body.into(),
                account_id: "000000000000".into(),
                region: "us-east-1".into(),
                request_id: "dns-test".into(),
            })
            .await;
        let status = response.status();
        let text = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(status.is_success(), "{status}: {text}");
        text
    }
    fn element(text: &str, tag: &str) -> String {
        text.split(&format!("<{tag}>"))
            .nth(1)
            .unwrap()
            .split('<')
            .next()
            .unwrap()
            .into()
    }
    async fn fixture() -> (
        Arc<Ec2Handler>,
        String,
        crate::TaskNetworkLease,
        crate::TaskNetworkLease,
    ) {
        // Standalone topology fixture; operator IAM has separate integration coverage.
        let ec2 = Arc::new(Ec2Handler::default());
        let vpc = element(
            &call(&ec2, "Action=CreateVpc&CidrBlock=10.6.0.0%2F16".into()).await,
            "vpcId",
        );
        let subnet = element(
            &call(
                &ec2,
                format!("Action=CreateSubnet&VpcId={vpc}&CidrBlock=10.6.1.0%2F24"),
            )
            .await,
            "subnetId",
        );
        let group = element(
            &call(
                &ec2,
                format!(
                    "Action=CreateSecurityGroup&VpcId={vpc}&GroupName=dns&GroupDescription=dns"
                ),
            )
            .await,
            "groupId",
        );
        let source = ec2
            .reserve_task_network(
                "000000000000",
                "us-east-1",
                &subnet,
                std::slice::from_ref(&group),
                "source",
            )
            .unwrap();
        let target = ec2
            .reserve_task_network(
                "000000000000",
                "us-east-1",
                &subnet,
                std::slice::from_ref(&group),
                "rds",
            )
            .unwrap();
        assert!(target.set_dns_name("orders.us-east-1.rds.amazonaws.com"));
        let endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(target.set_endpoint(5432, endpoint.local_addr().unwrap()));
        (ec2, vpc, source, target)
    }
    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }
    async fn listeners() -> (UdpSocket, TcpListener, SocketAddr, SocketAddr) {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        let tcp_address = tcp.local_addr().unwrap();
        (udp, tcp, udp_address, tcp_address)
    }
    async fn stop(tasks: [JoinHandle<()>; 2]) {
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
    async fn receive_udp(client: &UdpSocket) -> Vec<u8> {
        let mut packet = vec![0u8; MAX_PACKET + 1];
        let size = timeout(Duration::from_secs(1), client.recv(&mut packet))
            .await
            .unwrap()
            .unwrap();
        packet.truncate(size);
        packet
    }

    #[test]
    fn validates_questions_and_reply_identity_without_compression_loops() {
        let packet = query("example.invalid", 1);
        assert_eq!(question(&packet).unwrap().name, "example.invalid");
        let mut reply = packet.clone();
        reply[2] |= 0x80;
        assert!(valid_reply(&packet, &reply));
        reply[12] = 0xc0;
        assert!(!valid_reply(&packet, &reply));
        let mut malformed = packet;
        malformed[12] = 0xc0;
        assert!(question(&malformed).is_none());
        assert!(question(&malformed[..12]).is_none());
    }

    #[tokio::test]
    async fn managed_udp_tcp_follow_dns_toggle_target_and_source_lease_lifetime() {
        let (ec2, vpc, source, target) = fixture().await;
        let (udp, tcp, udp_address, tcp_address) = listeners().await;
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tasks = serve(
            udp,
            tcp,
            upstream.local_addr().unwrap(),
            ec2.clone(),
            "000000000000".into(),
            "us-east-1".into(),
            source.eni_id.clone(),
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(udp_address).await.unwrap();
        let request = query("ORDERS.us-east-1.rds.amazonaws.com", 1);
        client.send(&request).await.unwrap();
        let reply = receive_udp(&client).await;
        assert!(valid_reply(&request, &reply));
        assert_eq!(&reply[reply.len() - 4..], &target.private_ip.octets());
        assert_eq!(
            &reply[question(&request).unwrap().end + 6..question(&request).unwrap().end + 10],
            &[0, 0, 0, 0]
        );
        let mut stream = TcpStream::connect(tcp_address).await.unwrap();
        write_frame(&mut stream, &request).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), read_frame(&mut stream))
                .await
                .unwrap()
                .unwrap(),
            reply
        );
        let ipv6 = query("orders.us-east-1.rds.amazonaws.com", 28);
        write_frame(&mut stream, &ipv6).await.unwrap();
        let no_aaaa = timeout(Duration::from_secs(1), read_frame(&mut stream))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&no_aaaa[6..8], &[0, 0]);
        call(
            &ec2,
            format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsSupport.Value=false"),
        )
        .await;
        client.send(&request).await.unwrap();
        assert!(
            timeout(Duration::from_millis(60), client.recv(&mut [0; MAX_PACKET]))
                .await
                .is_err()
        );
        write_frame(&mut stream, &request).await.unwrap();
        assert!(timeout(Duration::from_secs(1), read_frame(&mut stream))
            .await
            .unwrap()
            .is_err());
        call(
            &ec2,
            format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsSupport.Value=true"),
        )
        .await;
        client.send(&request).await.unwrap();
        assert!(valid_reply(&request, &receive_udp(&client).await));
        drop(target);
        client.send(&request).await.unwrap();
        let mut packet = [0u8; MAX_PACKET];
        let (_, peer) = timeout(Duration::from_secs(1), upstream.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        // Unknown names are forwarded, never synthesized as stale managed ownership.
        let mut unknown = request.clone();
        unknown[2] |= 0x80;
        unknown[3] = 3; // actual upstream NXDOMAIN
        upstream.send_to(&unknown, peer).await.unwrap();
        assert_eq!(receive_udp(&client).await, unknown);
        drop(source);
        client.send(&request).await.unwrap();
        assert!(timeout(Duration::from_millis(60), client.recv(&mut packet))
            .await
            .is_err());
        stop(tasks).await;
    }

    #[tokio::test]
    async fn upstream_udp_tcp_eof_and_parent_abort_close_owned_workers() {
        let (ec2, vpc, source, _target) = fixture().await;
        let (upstream_udp, upstream_tcp, upstream_udp_address, upstream_tcp_address) =
            listeners().await;
        // UDP and TCP resolvers may use separate ephemeral ports in this contract test.
        let (udp, tcp, udp_address, _) = listeners().await;
        let tasks = serve(
            udp,
            tcp,
            upstream_udp_address,
            ec2.clone(),
            "000000000000".into(),
            "us-east-1".into(),
            source.eni_id.clone(),
        );
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(udp_address).await.unwrap();
        let request = query("unknown.invalid", 1);
        client.send(&request).await.unwrap();
        let mut received = [0u8; MAX_PACKET];
        let (size, peer) = timeout(
            Duration::from_secs(1),
            upstream_udp.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&received[..size], request.as_slice());
        let mut reply = request.clone();
        reply[2] |= 0x80;
        reply[3] = 3;
        upstream_udp.send_to(&reply, peer).await.unwrap();
        assert_eq!(receive_udp(&client).await, reply);
        client.send(&request).await.unwrap();
        let (_, peer) = timeout(
            Duration::from_secs(1),
            upstream_udp.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        call(
            &ec2,
            format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsSupport.Value=false"),
        )
        .await;
        upstream_udp.send_to(&reply, peer).await.unwrap();
        assert!(
            timeout(Duration::from_millis(60), client.recv(&mut received))
                .await
                .is_err(),
            "In-flight DNS replies must recheck current policy"
        );
        call(
            &ec2,
            format!("Action=ModifyVpcAttribute&VpcId={vpc}&EnableDnsSupport.Value=true"),
        )
        .await;
        client.send(&request).await.unwrap();
        let _ = timeout(
            Duration::from_secs(1),
            upstream_udp.recv_from(&mut received),
        )
        .await
        .unwrap()
        .unwrap();
        stop(tasks).await;
        assert!(
            timeout(Duration::from_millis(60), client.recv(&mut received))
                .await
                .is_err()
        );

        let (udp, tcp, _, tcp_address) = listeners().await;
        let tasks = serve(
            udp,
            tcp,
            upstream_tcp_address,
            ec2,
            "000000000000".into(),
            "us-east-1".into(),
            source.eni_id.clone(),
        );
        let mut stream = TcpStream::connect(tcp_address).await.unwrap();
        write_frame(&mut stream, &request).await.unwrap();
        let (mut resolver, _) = timeout(Duration::from_secs(1), upstream_tcp.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_frame(&mut resolver).await.unwrap(), request);
        write_frame(&mut resolver, &reply).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(1), read_frame(&mut stream))
                .await
                .unwrap()
                .unwrap(),
            reply
        );
        write_frame(&mut stream, &request).await.unwrap();
        let (mut resolver, _) = timeout(Duration::from_secs(1), upstream_tcp.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_frame(&mut resolver).await.unwrap(), request);
        resolver.write_all(&[0]).await.unwrap();
        drop(resolver); // partial length prefix must propagate Ok(Err(UnexpectedEof)).
        assert!(timeout(Duration::from_secs(1), read_frame(&mut stream))
            .await
            .unwrap()
            .is_err());
        let mut orphan = TcpStream::connect(tcp_address).await.unwrap();
        write_frame(&mut orphan, &request).await.unwrap();
        let (mut resolver, _) = timeout(Duration::from_secs(1), upstream_tcp.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_frame(&mut resolver).await.unwrap(), request);
        let mut malformed = TcpStream::connect(tcp_address).await.unwrap();
        malformed.write_all(&[0]).await.unwrap();
        malformed.shutdown().await.unwrap();
        drop(malformed);
        assert!(
            timeout(Duration::from_millis(60), upstream_tcp.accept())
                .await
                .is_err(),
            "Incomplete guest prefix must not open an upstream connection"
        );
        stop(tasks).await;
        assert_eq!(
            timeout(Duration::from_secs(1), resolver.read(&mut [0u8; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            timeout(Duration::from_secs(1), orphan.read(&mut [0u8; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}
