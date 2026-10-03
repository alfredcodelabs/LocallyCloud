//! Opt-in authoritative DNS for the committed Route 53 simple-record view.
//! The listener is loopback-only and never forwards queries or reads host DNS.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::{Record, RecordKey, Route53Service};

const MAX_PACKET: usize = 4096;
const UDP_LIMIT: usize = 512;
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

/// A DNS listener bound to one explicit account's public zones. Both transports use the
/// same local port. Dropping this handle also stops its tasks; `shutdown` joins them.
pub struct DnsServer {
    addr: SocketAddr,
    stop: watch::Sender<bool>,
    udp_task: JoinHandle<()>,
    tcp_task: JoinHandle<()>,
}

impl DnsServer {
    pub async fn start(
        service: Arc<Route53Service>,
        account_id: String,
        bind: SocketAddr,
    ) -> io::Result<Self> {
        if !bind.ip().is_loopback() || account_id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS requires a loopback bind and explicit account",
            ));
        }
        let tcp = TcpListener::bind(bind).await?;
        let addr = tcp.local_addr()?;
        let udp = UdpSocket::bind(addr).await?;
        let (stop, _) = watch::channel(false);
        let udp_task = tokio::spawn(run_udp(
            udp,
            service.clone(),
            account_id.clone(),
            stop.subscribe(),
        ));
        let tcp_task = tokio::spawn(run_tcp(tcp, service, account_id, stop.subscribe()));
        Ok(Self {
            addr,
            stop,
            udp_task,
            tcp_task,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.udp_task).await;
        let _ = (&mut self.tcp_task).await;
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.udp_task.abort();
        self.tcp_task.abort();
    }
}

async fn run_udp(
    socket: UdpSocket,
    service: Arc<Route53Service>,
    account: String,
    mut stop: watch::Receiver<bool>,
) {
    let mut packet = [0u8; MAX_PACKET];
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = socket.recv_from(&mut packet) => {
                let Ok((size, peer)) = result else { break };
                if let Some(response) = answer(&service, &account, &packet[..size], UDP_LIMIT) {
                    let _ = socket.send_to(&response, peer).await;
                }
            }
        }
    }
}

async fn run_tcp(
    listener: TcpListener,
    service: Arc<Route53Service>,
    account: String,
    mut stop: watch::Receiver<bool>,
) {
    let permits = Arc::new(Semaphore::new(32));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            result = listener.accept() => {
                let Ok((stream, _)) = result else { break };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                let service = service.clone();
                let account = account.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(TCP_TIMEOUT, serve_tcp(stream, &service, &account)).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn serve_tcp(
    mut stream: TcpStream,
    service: &Route53Service,
    account: &str,
) -> io::Result<()> {
    let length = stream.read_u16().await? as usize;
    if !(12..=MAX_PACKET).contains(&length) {
        return Ok(());
    }
    let mut packet = vec![0; length];
    stream.read_exact(&mut packet).await?;
    if let Some(response) = answer(service, account, &packet, MAX_PACKET) {
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
    }
    Ok(())
}

#[derive(Debug)]
struct Question {
    name: String,
    kind: u16,
    class: u16,
}

fn answer(service: &Route53Service, account: &str, packet: &[u8], limit: usize) -> Option<Vec<u8>> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let rd = packet[2] & 1 != 0;
    let parsed = parse_question(packet);
    let (question, rcode) = match parsed {
        Ok(question) => {
            let rcode = if question.class != 1 || !matches!(question.kind, 1 | 5 | 16 | 28) {
                4
            } else {
                0
            };
            (Some(question), rcode)
        }
        Err(()) => (None, 1),
    };
    let mut result = vec![0; 12];
    result[..2].copy_from_slice(&id.to_be_bytes());
    if let Some(question) = &question {
        if write_name(&mut result, &question.name).is_err() {
            return None;
        }
        result.extend_from_slice(&question.kind.to_be_bytes());
        result.extend_from_slice(&question.class.to_be_bytes());
    }
    let mut answer_count = 0u16;
    let mut authority_count = 0u16;
    let mut authoritative = false;
    let mut code = rcode;
    if rcode == 0 {
        let question = question.as_ref()?;
        let view = select_records(service, account, &question.name);
        if let Some((records, soa)) = view {
            authoritative = true;
            if records.is_empty() {
                code = 3;
            } else {
                let selected = records
                    .iter()
                    .find(|record| record_type(&record.key) == question.kind)
                    .or_else(|| {
                        records
                            .iter()
                            .find(|record| record.key.record_type == "CNAME")
                    });
                if let Some(record) = selected {
                    for value in &record.values {
                        let Some(rr) = encode_rr(record, value) else {
                            continue;
                        };
                        if result.len() + rr.len() > limit {
                            result[2] |= 0x02; // TC
                            break;
                        }
                        result.extend_from_slice(&rr);
                        answer_count += 1;
                    }
                }
            }
            if answer_count == 0 && result[2] & 0x02 == 0 {
                if let Some(soa) = soa.as_ref().and_then(|record| {
                    record
                        .values
                        .first()
                        .and_then(|value| encode_soa(record, value))
                }) {
                    if result.len() + soa.len() <= limit {
                        result.extend_from_slice(&soa);
                        authority_count = 1;
                    } else {
                        result[2] |= 0x02;
                    }
                }
            }
        } else {
            code = 5; // REFUSED: no visible authoritative zone, no recursion.
        }
    }
    result[2] |= 0x80 | if authoritative { 0x04 } else { 0 } | if rd { 0x01 } else { 0 };
    result[3] = code;
    result[4..6].copy_from_slice(&u16::from(question.is_some()).to_be_bytes());
    result[6..8].copy_from_slice(&answer_count.to_be_bytes());
    result[8..10].copy_from_slice(&authority_count.to_be_bytes());
    if result.len() > limit {
        result.truncate(limit);
        result[2] |= 0x02;
    }
    Some(result)
}

fn parse_question(packet: &[u8]) -> Result<Question, ()> {
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qd = u16::from_be_bytes([packet[4], packet[5]]);
    let an = u16::from_be_bytes([packet[6], packet[7]]);
    let ns = u16::from_be_bytes([packet[8], packet[9]]);
    let ar = u16::from_be_bytes([packet[10], packet[11]]);
    if flags & !0x0100 != 0 || qd != 1 || an != 0 || ns != 0 || ar != 0 {
        return Err(());
    }
    let (name, end) = read_name(packet, 12)?;
    let tail = packet.get(end..end + 4).ok_or(())?;
    if end + 4 != packet.len() {
        return Err(());
    }
    Ok(Question {
        name,
        kind: u16::from_be_bytes([tail[0], tail[1]]),
        class: u16::from_be_bytes([tail[2], tail[3]]),
    })
}

fn read_name(packet: &[u8], start: usize) -> Result<(String, usize), ()> {
    let mut at = start;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut total = 1usize;
    let mut hops = 0;
    loop {
        let length = *packet.get(at).ok_or(())?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(at + 1).ok_or(())?;
            let pointer = (((length as usize) & 0x3f) << 8) | low as usize;
            if pointer < 12 || pointer >= at || hops >= 16 {
                return Err(());
            }
            resume.get_or_insert(at + 2);
            at = pointer;
            hops += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(());
        }
        at += 1;
        if length == 0 {
            break;
        }
        let bytes = packet.get(at..at + length as usize).ok_or(())?;
        if bytes
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && *b != b'-' && *b != b'_')
        {
            return Err(());
        }
        total += length as usize + 1;
        if total > 255 || labels.len() >= 127 {
            return Err(());
        }
        labels.push(String::from_utf8(bytes.to_ascii_lowercase()).map_err(|_| ())?);
        at += length as usize;
    }
    Ok((format!("{}.", labels.join(".")), resume.unwrap_or(at)))
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), ()> {
    if name == "." {
        out.push(0);
        return Ok(());
    }
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(());
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn select_records(
    service: &Route53Service,
    account: &str,
    name: &str,
) -> Option<(Vec<Record>, Option<Record>)> {
    let accounts = service.accounts.lock().ok()?;
    let account = accounts.get(account)?;
    let mut candidates: Vec<_> = account
        .zones
        .values()
        .filter(|zone| name == zone.name || name.ends_with(&format!(".{}", zone.name)))
        .collect();
    candidates.sort_by_key(|zone| std::cmp::Reverse(zone.name.len()));
    let zone = *candidates.first()?;
    if candidates
        .get(1)
        .is_some_and(|other| other.name.len() == zone.name.len())
    {
        return None;
    }
    let mut kinds = std::collections::BTreeSet::new();
    let mut records = Vec::new();
    for record in zone
        .records
        .values()
        .filter(|record| record.key.name == name)
    {
        if kinds.insert(record.key.record_type.as_str()) {
            if let Some(selected) = service.selected(
                account,
                zone.records.values().filter(|candidate| {
                    candidate.key.name == name
                        && candidate.key.record_type == record.key.record_type
                }),
            ) {
                records.push(selected);
            }
        }
    }
    let soa = zone
        .records
        .get(&RecordKey {
            name: zone.name.clone(),
            record_type: "SOA".into(),
            identifier: None,
        })
        .cloned();
    Some((records, soa))
}

fn record_type(key: &RecordKey) -> u16 {
    match key.record_type.as_str() {
        "A" => 1,
        "CNAME" => 5,
        "TXT" => 16,
        "AAAA" => 28,
        _ => 0,
    }
}

fn encode_rr(record: &Record, value: &str) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    let kind = record_type(&record.key);
    match kind {
        1 => data.extend_from_slice(&value.parse::<std::net::Ipv4Addr>().ok()?.octets()),
        28 => data.extend_from_slice(&value.parse::<std::net::Ipv6Addr>().ok()?.octets()),
        5 => write_name(&mut data, value).ok()?,
        16 => {
            let text = value.strip_prefix('"')?.strip_suffix('"')?;
            let text = decode_txt(text)?;
            data.push(text.len().try_into().ok()?);
            data.extend_from_slice(&text);
        }
        _ => return None,
    }
    let mut rr = Vec::with_capacity(12 + data.len());
    rr.extend_from_slice(&[0xc0, 0x0c]);
    rr.extend_from_slice(&kind.to_be_bytes());
    rr.extend_from_slice(&1u16.to_be_bytes());
    rr.extend_from_slice(&record.ttl.to_be_bytes());
    rr.extend_from_slice(&(data.len() as u16).to_be_bytes());
    rr.extend_from_slice(&data);
    Some(rr)
}

fn decode_txt(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut input = text.bytes();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let first = input.next()?;
        if first.is_ascii_digit() {
            let second = input.next()?;
            let third = input.next()?;
            if !second.is_ascii_digit() || !third.is_ascii_digit() {
                return None;
            }
            let value =
                (first - b'0') as u16 * 100 + (second - b'0') as u16 * 10 + (third - b'0') as u16;
            bytes.push(value.try_into().ok()?);
        } else {
            bytes.push(first);
        }
        if bytes.len() > 255 {
            return None;
        }
    }
    (bytes.len() <= 255).then_some(bytes)
}

fn encode_soa(record: &Record, value: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 7 {
        return None;
    }
    let mut data = Vec::new();
    write_name(&mut data, parts[0]).ok()?;
    write_name(&mut data, parts[1]).ok()?;
    for field in &parts[2..] {
        data.extend_from_slice(&field.parse::<u32>().ok()?.to_be_bytes());
    }
    let mut rr = Vec::new();
    write_name(&mut rr, &record.key.name).ok()?;
    rr.extend_from_slice(&6u16.to_be_bytes());
    rr.extend_from_slice(&1u16.to_be_bytes());
    rr.extend_from_slice(&record.ttl.to_be_bytes());
    rr.extend_from_slice(&(data.len() as u16).to_be_bytes());
    rr.extend_from_slice(&data);
    Some(rr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{default_records, Account, Zone};

    fn fixture() -> Arc<Route53Service> {
        let service = Arc::new(Route53Service::new());
        let mut records = default_records("example.test.");
        for (name, kind, value) in [
            ("a.example.test.", "A", "192.0.2.7"),
            ("aaaa.example.test.", "AAAA", "2001:db8::7"),
            ("alias.example.test.", "CNAME", "a.example.test."),
            ("txt.example.test.", "TXT", "\"hello\\032world\""),
        ] {
            let key = RecordKey {
                name: name.into(),
                record_type: kind.into(),
                identifier: None,
            };
            records.insert(
                key.clone(),
                Record {
                    key,
                    ttl: 60,
                    values: vec![value.into()],
                    failover: None,
                    health_check_id: None,
                },
            );
        }
        let mut account = Account::default();
        account.zones.insert(
            "Z1".into(),
            Zone {
                id: "Z1".into(),
                name: "example.test.".into(),
                caller_reference: "test".into(),
                comment: String::new(),
                records,
            },
        );
        service
            .accounts
            .lock()
            .unwrap()
            .insert("111111111111".into(), account);
        service
    }

    fn query(name: &str, kind: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        write_name(&mut packet, name).unwrap();
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet
    }

    #[test]
    fn records_negative_answers_and_account_scope() {
        let service = fixture();
        for (name, kind, data) in [
            ("a.example.test.", 1, vec![192, 0, 2, 7]),
            (
                "aaaa.example.test.",
                28,
                "2001:db8::7"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ),
            (
                "alias.example.test.",
                5,
                vec![
                    1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's',
                    b't', 0,
                ],
            ),
            (
                "txt.example.test.",
                16,
                [vec![11], b"hello world".to_vec()].concat(),
            ),
        ] {
            let response = answer(&service, "111111111111", &query(name, kind), UDP_LIMIT).unwrap();
            assert_eq!(response[3], 0);
            assert_eq!(u16::from_be_bytes([response[6], response[7]]), 1);
            assert!(response.ends_with(&data));
            assert_eq!(response[2] & 0x84, 0x84); // QR, AA
        }
        let missing = answer(
            &service,
            "111111111111",
            &query("missing.example.test.", 1),
            UDP_LIMIT,
        )
        .unwrap();
        assert_eq!(missing[3], 3); // NXDOMAIN with SOA authority
        assert_eq!(u16::from_be_bytes([missing[8], missing[9]]), 1);
        let nodata = answer(
            &service,
            "111111111111",
            &query("a.example.test.", 28),
            UDP_LIMIT,
        )
        .unwrap();
        assert_eq!(nodata[3], 0);
        assert_eq!(u16::from_be_bytes([nodata[8], nodata[9]]), 1);
        let other = answer(
            &service,
            "222222222222",
            &query("a.example.test.", 1),
            UDP_LIMIT,
        )
        .unwrap();
        assert_eq!(other[3], 5); // REFUSED, not a cross-account answer
    }

    #[test]
    fn malformed_and_unsupported_queries_do_not_panic_or_escape() {
        let service = fixture();
        assert!(answer(&service, "111111111111", &[0; 5], UDP_LIMIT).is_none());
        let mut looped = query("a.example.test.", 1);
        looped[12] = 0xc0;
        looped[13] = 12;
        assert_eq!(
            answer(&service, "111111111111", &looped, UDP_LIMIT).unwrap()[3],
            1
        );
        let mut extra = query("a.example.test.", 1);
        extra[11] = 1; // EDNS/additional unsupported
        assert_eq!(
            answer(&service, "111111111111", &extra, UDP_LIMIT).unwrap()[3],
            1
        );
        let any = answer(
            &service,
            "111111111111",
            &query("a.example.test.", 255),
            UDP_LIMIT,
        )
        .unwrap();
        assert_eq!(any[3], 4); // NOTIMP
        let outside = answer(&service, "111111111111", &query("else.test.", 1), UDP_LIMIT).unwrap();
        assert_eq!(outside[3], 5); // REFUSED
    }

    #[test]
    fn dns_answer_tracks_failover_health() {
        use crate::HealthCheck;
        use std::sync::atomic::{AtomicBool, Ordering};
        let service = fixture();
        {
            let mut accounts = service.accounts.lock().unwrap();
            let account = accounts.get_mut("111111111111").unwrap();
            let zone = account.zones.get_mut("Z1").unwrap();
            let key = RecordKey {
                name: "app.example.test.".into(),
                record_type: "A".into(),
                identifier: Some("east".into()),
            };
            zone.records.insert(
                key.clone(),
                Record {
                    key,
                    ttl: 0,
                    values: vec!["192.0.2.1".into()],
                    failover: Some("PRIMARY".into()),
                    health_check_id: Some("east".into()),
                },
            );
            let key = RecordKey {
                name: "app.example.test.".into(),
                record_type: "A".into(),
                identifier: Some("west".into()),
            };
            zone.records.insert(
                key.clone(),
                Record {
                    key,
                    ttl: 0,
                    values: vec!["192.0.2.2".into()],
                    failover: Some("SECONDARY".into()),
                    health_check_id: Some("west".into()),
                },
            );
            for id in ["east", "west"] {
                account.health_checks.insert(
                    id.into(),
                    HealthCheck {
                        id: id.into(),
                        caller_reference: id.into(),
                        routing_control_arn: id.into(),
                    },
                );
            }
        }
        let packet = query("app.example.test.", 1);
        let response = answer(&service, "111111111111", &packet, UDP_LIMIT).unwrap();
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 1]);
        let east_on = Arc::new(AtomicBool::new(true));
        let state = east_on.clone();
        service.set_routing_control_resolver(Arc::new(move |arn| {
            Some(if arn == "east" {
                state.load(Ordering::SeqCst)
            } else {
                true
            })
        }));
        let response = answer(&service, "111111111111", &packet, UDP_LIMIT).unwrap();
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 1]);
        east_on.store(false, Ordering::SeqCst);
        let response = answer(&service, "111111111111", &packet, UDP_LIMIT).unwrap();
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 2]);
    }

    #[test]
    fn large_rrset_truncates_udp_but_fits_tcp_and_duplicate_zone_is_refused() {
        let service = fixture();
        {
            let mut accounts = service.accounts.lock().unwrap();
            let account = accounts.get_mut("111111111111").unwrap();
            let zone = account.zones.get_mut("Z1").unwrap();
            let record = zone
                .records
                .get_mut(&RecordKey {
                    name: "a.example.test.".into(),
                    record_type: "A".into(),
                    identifier: None,
                })
                .unwrap();
            record.values = (1..=100).map(|i| format!("192.0.2.{i}")).collect();
        }
        let packet = query("a.example.test.", 1);
        let udp = answer(&service, "111111111111", &packet, UDP_LIMIT).unwrap();
        assert!(udp[2] & 0x02 != 0);
        assert!(udp.len() <= UDP_LIMIT);
        let tcp = answer(&service, "111111111111", &packet, MAX_PACKET).unwrap();
        assert_eq!(u16::from_be_bytes([tcp[6], tcp[7]]), 100);
        assert_eq!(tcp[2] & 0x02, 0);
        {
            let mut accounts = service.accounts.lock().unwrap();
            let account = accounts.get_mut("111111111111").unwrap();
            let duplicate = account.zones.get("Z1").unwrap().clone();
            account.zones.insert("Z2".into(), duplicate);
        }
        let ambiguous = answer(&service, "111111111111", &packet, UDP_LIMIT).unwrap();
        assert_eq!(ambiguous[3], 5);
    }

    #[tokio::test]
    async fn udp_tcp_and_shutdown_share_port() {
        let server = DnsServer::start(
            fixture(),
            "111111111111".into(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let packet = query("a.example.test.", 1);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&packet, addr).await.unwrap();
        let mut buffer = [0; 512];
        let (size, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(buffer[3], 0);
        assert_eq!(buffer[size - 4..size], [192, 0, 2, 7]);
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_u16(packet.len() as u16).await.unwrap();
        tcp.write_all(&packet).await.unwrap();
        let length = timeout(Duration::from_secs(2), tcp.read_u16())
            .await
            .unwrap()
            .unwrap() as usize;
        let mut answer = vec![0; length];
        tcp.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[length - 4..], [192, 0, 2, 7]);
        server.shutdown().await;
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
