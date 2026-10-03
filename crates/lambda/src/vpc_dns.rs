//! Bounded AmazonProvidedDNS relay for an isolated OCI Lambda.
//! DNS reaches only the host's configured resolver; application TCP still uses EC2 NAT policy.
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use locallycloud_ec2::Ec2Handler;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const MAX_PACKET: usize = 4096;
const TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn system_resolver() -> io::Result<SocketAddr> {
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

fn valid_query(packet: &[u8]) -> bool {
    (12..=MAX_PACKET).contains(&packet.len())
        && packet[2] & 0xf8 == 0 // request with standard QUERY opcode
        && packet[4..6] == [0, 1] // one question
}

fn valid_reply(query: &[u8], reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[0..2] == query[0..2] && reply[2] & 0x80 != 0
}

pub(crate) fn serve(
    udp: UdpSocket,
    tcp: TcpListener,
    upstream: SocketAddr,
    ec2: Arc<Ec2Handler>,
    account: String,
    region: String,
    eni: String,
) -> [tokio::task::JoinHandle<()>; 2] {
    let udp = Arc::new(udp);
    let udp_ec2 = ec2.clone();
    let udp_account = account.clone();
    let udp_region = region.clone();
    let udp_eni = eni.clone();
    let udp_task = tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(64));
        let mut packet = [0u8; MAX_PACKET + 1];
        while let Ok((size, peer)) = udp.recv_from(&mut packet).await {
            if !valid_query(&packet[..size])
                || !udp_ec2.vpc_dns_enabled(&udp_account, &udp_region, &udp_eni)
            {
                continue;
            }
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let query = packet[..size].to_vec();
            let udp = udp.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let bind = if upstream.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let Ok(Ok(socket)) = tokio::time::timeout(TIMEOUT, UdpSocket::bind(bind)).await
                else {
                    return;
                };
                if socket.connect(upstream).await.is_err() || socket.send(&query).await.is_err() {
                    return;
                }
                let mut reply = [0u8; MAX_PACKET + 1];
                let Ok(Ok(size)) = tokio::time::timeout(TIMEOUT, socket.recv(&mut reply)).await
                else {
                    return;
                };
                if size <= MAX_PACKET && valid_reply(&query, &reply[..size]) {
                    let _ = udp.send_to(&reply[..size], peer).await;
                }
            });
        }
    });
    let tcp_task = tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(32));
        while let Ok((mut guest, _)) = tcp.accept().await {
            if !ec2.vpc_dns_enabled(&account, &region, &eni) {
                continue;
            }
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let ec2 = ec2.clone();
            let account = account.clone();
            let region = region.clone();
            let eni = eni.clone();
            tokio::spawn(async move {
                let _slot = slot;
                let Ok(Ok(mut resolver)) =
                    tokio::time::timeout(TIMEOUT, TcpStream::connect(upstream)).await
                else {
                    return;
                };
                loop {
                    if !ec2.vpc_dns_enabled(&account, &region, &eni) {
                        break;
                    }
                    let mut length = [0u8; 2];
                    if tokio::time::timeout(TIMEOUT, guest.read_exact(&mut length))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let size = u16::from_be_bytes(length) as usize;
                    if !(12..=MAX_PACKET).contains(&size) {
                        break;
                    }
                    let mut query = vec![0u8; size];
                    if tokio::time::timeout(TIMEOUT, guest.read_exact(&mut query))
                        .await
                        .is_err()
                        || !valid_query(&query)
                    {
                        break;
                    }
                    if resolver.write_all(&length).await.is_err()
                        || resolver.write_all(&query).await.is_err()
                    {
                        break;
                    }
                    if tokio::time::timeout(TIMEOUT, resolver.read_exact(&mut length))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    let size = u16::from_be_bytes(length) as usize;
                    if !(12..=MAX_PACKET).contains(&size) {
                        break;
                    }
                    let mut reply = vec![0u8; size];
                    if tokio::time::timeout(TIMEOUT, resolver.read_exact(&mut reply))
                        .await
                        .is_err()
                        || !valid_reply(&query, &reply)
                    {
                        break;
                    }
                    if guest.write_all(&length).await.is_err()
                        || guest.write_all(&reply).await.is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
    [udp_task, tcp_task]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_queries_and_mismatched_replies() {
        let query = [0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        assert!(valid_query(&query));
        let mut reply = query;
        reply[2] |= 0x80;
        assert!(valid_reply(&query, &reply));
        reply[0] = 0xff;
        assert!(!valid_reply(&query, &reply));
        assert!(!valid_query(&reply));
        assert!(!valid_query(&query[..11]));
    }
}
