//! Account-global Route 53 public zones and simple record sets.
//! Unsupported Route 53 operations fail with an XML error.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::response::Response;
use localcloud_core::handler::{NativeHandler, ServiceRequest};
use localcloud_core::registry::{AwsProtocol, ServiceMetadata, ServiceName, ServiceRegistry};
use quick_xml::events::Event;
use quick_xml::Reader;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub mod dns;
pub use dns::DnsServer;

const XMLNS: &str = "https://route53.amazonaws.com/doc/2013-04-01/";
const ROOT: &str = "/2013-04-01";
const MAX_XML: usize = 1024 * 1024;

#[derive(Clone, Debug, Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn one(&self, name: &str) -> Result<Option<&Node>, Error> {
        let mut found = self.children.iter().filter(|child| child.name == name);
        let first = found.next();
        if found.next().is_some() {
            return Err(Error::invalid("Duplicate XML element"));
        }
        Ok(first)
    }

    fn required(&self, name: &str) -> Result<&Node, Error> {
        self.one(name)?
            .ok_or_else(|| Error::invalid("Missing required XML element"))
    }

    fn value(&self, name: &str) -> Result<Option<&str>, Error> {
        Ok(self.one(name)?.map(|node| node.text.as_str()))
    }

    fn required_value(&self, name: &str) -> Result<&str, Error> {
        Ok(self.required(name)?.text.as_str())
    }

    fn only(&self, allowed: &[&str]) -> Result<(), Error> {
        if self
            .children
            .iter()
            .any(|child| !allowed.contains(&child.name.as_str()))
        {
            return Err(Error::invalid("Unsupported XML element"));
        }
        Ok(())
    }
}

fn parse_xml(bytes: &[u8], root: &str) -> Result<Node, Error> {
    if bytes.len() > MAX_XML {
        return Err(Error::invalid("XML request is too large"));
    }
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Node> = Vec::new();
    let mut complete = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = String::from_utf8(start.name().as_ref().as_bytes().to_vec())
                    .map_err(|_| Error::invalid("Invalid XML name"))?;
                if name.contains(':') || stack.len() > 12 {
                    return Err(Error::invalid("Unsupported XML namespace or depth"));
                }
                if stack.is_empty() {
                    let mut namespace = None;
                    for attr in start.attributes() {
                        let attr = attr.map_err(|_| Error::invalid("Invalid XML attribute"))?;
                        if attr.key.as_ref() != "xmlns" {
                            return Err(Error::invalid("Unsupported XML attribute"));
                        }
                        namespace = Some(
                            attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map_err(|_| Error::invalid("Invalid XML namespace"))?
                                .into_owned(),
                        );
                    }
                    if namespace.as_deref() != Some(XMLNS) {
                        return Err(Error::invalid("Invalid XML namespace"));
                    }
                } else if start.attributes().next().is_some() {
                    return Err(Error::invalid("Unsupported XML attribute"));
                }
                stack.push(Node {
                    name,
                    ..Node::default()
                });
            }
            Ok(Event::Empty(start)) => {
                let name = String::from_utf8(start.name().as_ref().as_bytes().to_vec())
                    .map_err(|_| Error::invalid("Invalid XML name"))?;
                if start.attributes().next().is_some() || stack.is_empty() {
                    return Err(Error::invalid("Unsupported empty XML element"));
                }
                stack.last_mut().unwrap().children.push(Node {
                    name,
                    ..Node::default()
                });
            }
            Ok(Event::Text(text)) => {
                let text = quick_xml::escape::unescape(text.as_ref())
                    .map_err(|_| Error::invalid("Invalid XML text"))?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return Err(Error::invalid("Text outside XML document"));
                }
            }
            Ok(Event::End(end)) => {
                let node = stack
                    .pop()
                    .ok_or_else(|| Error::invalid("Unexpected XML close"))?;
                if node.name != end.name().as_ref() {
                    return Err(Error::invalid("Mismatched XML close"));
                }
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if complete.replace(node).is_some() {
                    return Err(Error::invalid("Multiple XML roots"));
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                let encoded = format!("&{};", reference.as_ref());
                let value = quick_xml::escape::unescape(&encoded)
                    .map_err(|_| Error::invalid("Invalid XML reference"))?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                } else {
                    return Err(Error::invalid("Reference outside XML document"));
                }
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_)) => {}
            Ok(Event::DocType(_))
            | Ok(Event::PI(_))
            | Ok(Event::CData(_))
            | Ok(Event::Comment(_)) => {
                return Err(Error::invalid("Unsupported XML construct"));
            }
            Err(_) => return Err(Error::invalid("Malformed XML")),
        }
    }
    if !stack.is_empty() {
        return Err(Error::invalid("Unclosed XML element"));
    }
    let node = complete.ok_or_else(|| Error::invalid("Empty XML request"))?;
    if node.name != root {
        return Err(Error::invalid("Unexpected XML root"));
    }
    Ok(node)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecordKey {
    name: String,
    record_type: String,
    identifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    key: RecordKey,
    ttl: u32,
    values: Vec<String>,
    failover: Option<String>,
    health_check_id: Option<String>,
}

#[derive(Clone)]
struct HealthCheck {
    id: String,
    caller_reference: String,
    routing_control_arn: String,
}

#[derive(Clone)]
struct Zone {
    id: String,
    name: String,
    caller_reference: String,
    comment: String,
    records: BTreeMap<RecordKey, Record>,
}

#[derive(Clone)]
struct Change {
    id: String,
    submitted_at: String,
    status: &'static str,
}

#[derive(Default)]
struct Account {
    next_zone: u64,
    next_change: u64,
    zones: BTreeMap<String, Zone>,
    caller_refs: BTreeMap<String, String>,
    changes: BTreeMap<String, Change>,
    next_health_check: u64,
    health_checks: BTreeMap<String, HealthCheck>,
}

pub type RoutingControlResolver = Arc<dyn Fn(&str) -> Option<bool> + Send + Sync>;

pub struct Route53Service {
    accounts: Mutex<BTreeMap<String, Account>>,
    routing_control: Mutex<Option<RoutingControlResolver>>,
}

impl Default for Route53Service {
    fn default() -> Self {
        Self {
            accounts: Mutex::new(BTreeMap::new()),
            routing_control: Mutex::new(None),
        }
    }
}

impl Route53Service {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an ARC routing-control state reader. Unknown controls fail closed.
    pub fn set_routing_control_resolver(&self, resolver: RoutingControlResolver) {
        *self.routing_control.lock().expect("routing-control lock") = Some(resolver);
    }

    fn healthy(&self, account: &Account, record: &Record) -> bool {
        let Some(id) = &record.health_check_id else {
            return true;
        };
        let Some(check) = account.health_checks.get(id) else {
            return false;
        };
        self.routing_control
            .lock()
            .ok()
            .and_then(|reader| {
                reader
                    .as_ref()
                    .and_then(|reader| reader(&check.routing_control_arn))
            })
            .unwrap_or(false)
    }

    fn selected<'a>(
        &self,
        account: &Account,
        records: impl Iterator<Item = &'a Record>,
    ) -> Option<Record> {
        let records: Vec<_> = records.collect();
        if records.iter().any(|r| r.failover.is_some()) {
            let primary = records
                .iter()
                .find(|r| r.failover.as_deref() == Some("PRIMARY"));
            let secondary = records
                .iter()
                .find(|r| r.failover.as_deref() == Some("SECONDARY"));
            return primary
                .filter(|r| self.healthy(account, r))
                .or_else(|| secondary.filter(|r| self.healthy(account, r)))
                .or(primary)
                .map(|record| (*record).clone());
        }
        records.first().map(|r| (*r).clone())
    }

    /// Read-only DNS evidence for ACM and other in-process consumers.
    /// Only committed simple records are exposed; the ordinary AWS region is irrelevant.
    pub fn resolve_records(&self, account_id: &str, name: &str, record_type: &str) -> Vec<String> {
        let Ok(name) = canonical_name(name) else {
            return Vec::new();
        };
        let Ok(accounts) = self.accounts.lock() else {
            return Vec::new();
        };
        let Some(account) = accounts.get(account_id) else {
            return Vec::new();
        };
        let records = account
            .zones
            .values()
            .filter(|zone| name == zone.name || name.ends_with(&format!(".{}", zone.name)))
            .flat_map(|zone| {
                zone.records.values().filter(|record| {
                    record.key.name == name && record.key.record_type == record_type
                })
            });
        self.selected(account, records)
            .map(|record| record.values)
            .unwrap_or_default()
    }

    fn dispatch(&self, request: &ServiceRequest) -> Result<Output, Error> {
        let path = request.uri.path();
        let segments: Vec<_> = path.trim_matches('/').split('/').collect();
        if segments.first() != Some(&"2013-04-01") {
            return Err(Error::new(
                "InvalidInput",
                400,
                "Unsupported Route 53 operation",
            ));
        }
        let account_id = request.account_id.as_str();
        match (request.method.as_str(), segments.as_slice()) {
            ("POST", ["2013-04-01", "hostedzone"]) => self.create_zone(account_id, &request.body),
            ("GET", ["2013-04-01", "hostedzone"]) => {
                self.list_zones(account_id, request.uri.query())
            }
            ("GET", ["2013-04-01", "hostedzone", id]) => self.get_zone(account_id, id),
            ("DELETE", ["2013-04-01", "hostedzone", id]) => self.delete_zone(account_id, id),
            ("POST", ["2013-04-01", "hostedzone", id, "rrset"]) => {
                self.change_records(account_id, id, &request.body)
            }
            ("GET", ["2013-04-01", "hostedzone", id, "rrset"]) => {
                self.list_records(account_id, id, request.uri.query())
            }
            ("GET", ["2013-04-01", "change", id]) => self.get_change(account_id, id),
            ("POST", ["2013-04-01", "healthcheck"]) => {
                self.create_health_check(account_id, &request.body)
            }
            ("GET", ["2013-04-01", "healthcheck"]) => self.list_health_checks(account_id),
            ("GET", ["2013-04-01", "healthcheck", id]) => self.get_health_check(account_id, id),
            ("DELETE", ["2013-04-01", "healthcheck", id]) => {
                self.delete_health_check(account_id, id)
            }
            _ => Err(Error::new(
                "InvalidInput",
                400,
                "Unsupported Route 53 operation",
            )),
        }
    }

    fn create_health_check(&self, account_id: &str, body: &[u8]) -> Result<Output, Error> {
        let root = parse_xml(body, "CreateHealthCheckRequest")?;
        root.only(&["CallerReference", "HealthCheckConfig"])?;
        let caller = root.required_value("CallerReference")?;
        if caller.is_empty() || caller.len() > 64 {
            return Err(Error::invalid("Invalid CallerReference"));
        }
        let config = root.required("HealthCheckConfig")?;
        config.only(&["Type", "RoutingControlArn"])?;
        if config.required_value("Type")? != "RECOVERY_CONTROL" {
            return Err(Error::invalid(
                "Only RECOVERY_CONTROL health checks are supported",
            ));
        }
        let arn = config.required_value("RoutingControlArn")?;
        let parts: Vec<_> = arn.splitn(6, ':').collect();
        if parts.len() != 6
            || parts[0] != "arn"
            || parts[1] != "aws"
            || parts[2] != "route53-recovery-control"
            || !parts[3].is_empty()
            || parts[4] != account_id
            || !parts[5].starts_with("controlpanel/")
            || !parts[5].contains("/routingcontrol/")
            || arn.len() > 255
        {
            return Err(Error::invalid("Invalid RoutingControlArn"));
        }
        let exists = self
            .routing_control
            .lock()
            .map_err(|_| Error::internal())?
            .as_ref()
            .is_some_and(|resolve| resolve(arn).is_some());
        if !exists {
            return Err(Error::invalid(
                "RoutingControlArn does not identify an ARC routing control",
            ));
        }
        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts.entry(account_id.to_owned()).or_default();
        if account
            .health_checks
            .values()
            .any(|check| check.caller_reference == caller)
        {
            return Err(Error::new(
                "HealthCheckAlreadyExists",
                409,
                "CallerReference already exists",
            ));
        }
        account.next_health_check += 1;
        let id = format!(
            "{:08x}-0000-4000-8000-{:012x}",
            account.next_health_check, account.next_health_check
        );
        let check = HealthCheck {
            id: id.clone(),
            caller_reference: caller.to_owned(),
            routing_control_arn: arn.to_owned(),
        };
        let xml = format!("<HealthCheck>{}</HealthCheck>", health_check_fields(&check));
        account.health_checks.insert(id.clone(), check);
        Ok(Output::new(201, "CreateHealthCheckResponse", xml)
            .header("Location", format!("{ROOT}/healthcheck/{id}")))
    }

    fn list_health_checks(&self, account_id: &str) -> Result<Output, Error> {
        let accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let checks = accounts.get(account_id).map(|a| &a.health_checks);
        let xml = checks
            .into_iter()
            .flat_map(|checks| checks.values())
            .map(|check| format!("<HealthCheck>{}</HealthCheck>", health_check_fields(check)))
            .collect::<String>();
        Ok(Output::new(200, "ListHealthChecksResponse", format!("<HealthChecks>{xml}</HealthChecks><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems>")))
    }

    fn get_health_check(&self, account_id: &str, id: &str) -> Result<Output, Error> {
        let accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let check = accounts
            .get(account_id)
            .and_then(|a| a.health_checks.get(id))
            .ok_or_else(Error::no_health_check)?;
        Ok(Output::new(
            200,
            "GetHealthCheckResponse",
            format!("<HealthCheck>{}</HealthCheck>", health_check_fields(check)),
        ))
    }

    fn delete_health_check(&self, account_id: &str, id: &str) -> Result<Output, Error> {
        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts
            .get_mut(account_id)
            .ok_or_else(Error::no_health_check)?;
        if !account.health_checks.contains_key(id) {
            return Err(Error::no_health_check());
        }
        if account
            .zones
            .values()
            .flat_map(|zone| zone.records.values())
            .any(|record| record.health_check_id.as_deref() == Some(id))
        {
            return Err(Error::new(
                "HealthCheckInUse",
                400,
                "Health check is referenced by a record",
            ));
        }
        account.health_checks.remove(id);
        Ok(Output::new(200, "DeleteHealthCheckResponse", String::new()))
    }

    fn create_zone(&self, account_id: &str, body: &[u8]) -> Result<Output, Error> {
        let root = parse_xml(body, "CreateHostedZoneRequest")?;
        root.only(&[
            "Name",
            "CallerReference",
            "HostedZoneConfig",
            "DelegationSetId",
            "VPC",
        ])?;
        if root.one("DelegationSetId")?.is_some() || root.one("VPC")?.is_some() {
            return Err(Error::invalid(
                "Delegation sets and private zones are not supported",
            ));
        }
        let name = canonical_name(root.required_value("Name")?)?;
        let caller = root.required_value("CallerReference")?;
        if caller.is_empty() || caller.len() > 128 {
            return Err(Error::invalid("Invalid CallerReference"));
        }
        let mut comment = String::new();
        if let Some(config) = root.one("HostedZoneConfig")? {
            config.only(&["Comment", "PrivateZone"])?;
            if config.value("PrivateZone")? == Some("true") {
                return Err(Error::invalid("Private hosted zones are not supported"));
            }
            comment = config.value("Comment")?.unwrap_or("").to_owned();
        }
        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts.entry(account_id.to_owned()).or_default();
        if account.caller_refs.contains_key(caller) {
            return Err(Error::new(
                "HostedZoneAlreadyExists",
                409,
                "CallerReference already exists",
            ));
        }
        account.next_zone += 1;
        let id = format!("Z{:013X}", account.next_zone);
        let zone = Zone {
            id: id.clone(),
            name: name.clone(),
            caller_reference: caller.to_owned(),
            comment,
            records: default_records(&name),
        };
        let change = new_change(account);
        account.caller_refs.insert(caller.to_owned(), id.clone());
        account.zones.insert(id.clone(), zone.clone());
        let xml = format!(
            "<HostedZone>{}</HostedZone><ChangeInfo>{}</ChangeInfo>{}",
            zone_fields(&zone),
            change_fields(&change),
            delegation_set(&zone)
        );
        Ok(Output::new(201, "CreateHostedZoneResponse", xml)
            .header("Location", format!("{ROOT}/hostedzone/{id}")))
    }

    fn get_zone(&self, account_id: &str, id: &str) -> Result<Output, Error> {
        let accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let zone = find_zone(&accounts, account_id, id)?;
        let xml = format!(
            "<HostedZone>{}</HostedZone>{}",
            zone_fields(zone),
            delegation_set(zone)
        );
        Ok(Output::new(200, "GetHostedZoneResponse", xml))
    }

    fn list_zones(&self, account_id: &str, query: Option<&str>) -> Result<Output, Error> {
        let params = query_params(query)?;
        if params
            .keys()
            .any(|key| key != "marker" && key != "maxitems")
        {
            return Err(Error::invalid("Unsupported ListHostedZones filter"));
        }
        let max = parse_max(params.get("maxitems"), 100)?;
        let marker = params.get("marker").map(String::as_str);
        let accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let zones = accounts.get(account_id).map(|a| &a.zones);
        let all: Vec<_> = zones
            .into_iter()
            .flat_map(|z| z.values())
            .filter(|zone| marker.is_none_or(|marker| zone.id.as_str() >= marker))
            .collect();
        let next = all.get(max).map(|zone| zone.id.as_str());
        let listed = all
            .iter()
            .take(max)
            .map(|zone| format!("<HostedZone>{}</HostedZone>", zone_fields(zone)))
            .collect::<String>();
        let mut xml = format!(
            "<HostedZones>{listed}</HostedZones><IsTruncated>{}</IsTruncated>",
            next.is_some()
        );
        if let Some(marker) = marker {
            xml.push_str(&format!("<Marker>{}</Marker>", escape(marker)));
        }
        if let Some(next) = next {
            xml.push_str(&format!("<NextMarker>{}</NextMarker>", escape(next)));
        }
        xml.push_str(&format!("<MaxItems>{max}</MaxItems>"));
        Ok(Output::new(200, "ListHostedZonesResponse", xml))
    }

    fn delete_zone(&self, account_id: &str, id: &str) -> Result<Output, Error> {
        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts.get_mut(account_id).ok_or_else(Error::no_zone)?;
        let id = zone_id(id);
        let zone = account.zones.get(id).ok_or_else(Error::no_zone)?;
        if zone.records.len() > 2 {
            return Err(Error::new(
                "HostedZoneNotEmpty",
                400,
                "Hosted zone contains non-default records",
            ));
        }
        let caller = zone.caller_reference.clone();
        account.zones.remove(id);
        account.caller_refs.remove(&caller);
        let change = new_change(account);
        Ok(Output::new(
            200,
            "DeleteHostedZoneResponse",
            format!("<ChangeInfo>{}</ChangeInfo>", change_fields(&change)),
        ))
    }

    fn change_records(&self, account_id: &str, id: &str, body: &[u8]) -> Result<Output, Error> {
        let root = parse_xml(body, "ChangeResourceRecordSetsRequest")?;
        root.only(&["ChangeBatch"])?;
        let batch = root.required("ChangeBatch")?;
        batch.only(&["Comment", "Changes"])?;
        let changes = batch.required("Changes")?;
        if changes.children.is_empty() || changes.children.len() > 1000 {
            return Err(Error::change("Change batch must contain 1 to 1000 changes"));
        }
        if changes.children.iter().any(|child| child.name != "Change") {
            return Err(Error::change("Unsupported change element"));
        }

        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts.get_mut(account_id).ok_or_else(Error::no_zone)?;
        let id = zone_id(id);
        let zone = account.zones.get(id).ok_or_else(Error::no_zone)?;
        let mut candidate = zone.records.clone();
        let mut seen = BTreeSet::new();
        for item in &changes.children {
            item.only(&["Action", "ResourceRecordSet"])?;
            let action = item.required_value("Action")?;
            let record = parse_record(item.required("ResourceRecordSet")?, &zone.name)?;
            if !seen.insert(record.key.clone()) {
                return Err(Error::change(
                    "Repeated record identity in one change batch",
                ));
            }
            if record.key.name == zone.name
                && (record.key.record_type == "NS" || record.key.record_type == "SOA")
            {
                return Err(Error::change("Default apex records cannot be changed"));
            }
            match action {
                "CREATE" => {
                    if candidate.contains_key(&record.key) {
                        return Err(Error::change("Record already exists"));
                    }
                    candidate.insert(record.key.clone(), record);
                }
                "UPSERT" => {
                    candidate.insert(record.key.clone(), record);
                }
                "DELETE" => {
                    if candidate.get(&record.key) != Some(&record) {
                        return Err(Error::change("Record does not match existing record"));
                    }
                    candidate.remove(&record.key);
                }
                _ => return Err(Error::change("Unsupported change action")),
            }
        }
        validate_cname_conflicts(&candidate, &zone.name)?;
        validate_failover(&candidate, &account.health_checks)?;
        account
            .zones
            .get_mut(id)
            .expect("zone held under account lock")
            .records = candidate;
        let change = new_change(account);
        Ok(Output::new(
            200,
            "ChangeResourceRecordSetsResponse",
            format!("<ChangeInfo>{}</ChangeInfo>", change_fields(&change)),
        ))
    }

    fn list_records(
        &self,
        account_id: &str,
        id: &str,
        query: Option<&str>,
    ) -> Result<Output, Error> {
        let params = query_params(query)?;
        if params
            .keys()
            .any(|key| key != "name" && key != "type" && key != "maxitems")
        {
            return Err(Error::invalid("Unsupported ListResourceRecordSets cursor"));
        }
        let max = parse_max(params.get("maxitems"), 300)?;
        let start_name = params
            .get("name")
            .map(|name| canonical_name(name))
            .transpose()?;
        let start_type = params.get("type");
        let accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let zone = find_zone(&accounts, account_id, id)?;
        let mut records: Vec<_> = zone.records.values().collect();
        records.sort_by_key(|record| {
            (
                reverse_labels(&record.key.name),
                record.key.record_type.clone(),
                record.key.identifier.clone(),
            )
        });
        if let Some(name) = &start_name {
            let start = reverse_labels(name);
            records.retain(|record| {
                let current = reverse_labels(&record.key.name);
                current > start
                    || (current == start
                        && start_type
                            .is_none_or(|record_type| record.key.record_type >= *record_type))
            });
        }
        let next = records.get(max);
        let listed = records
            .iter()
            .take(max)
            .map(|record| record_fields(record))
            .collect::<String>();
        let mut xml = format!(
            "<ResourceRecordSets>{listed}</ResourceRecordSets><IsTruncated>{}</IsTruncated>",
            next.is_some()
        );
        if let Some(next) = next {
            xml.push_str(&format!(
                "<NextRecordName>{}</NextRecordName><NextRecordType>{}</NextRecordType>",
                escape(&next.key.name),
                next.key.record_type
            ));
        }
        xml.push_str(&format!("<MaxItems>{max}</MaxItems>"));
        Ok(Output::new(200, "ListResourceRecordSetsResponse", xml))
    }

    fn get_change(&self, account_id: &str, id: &str) -> Result<Output, Error> {
        let mut accounts = self.accounts.lock().map_err(|_| Error::internal())?;
        let account = accounts.get_mut(account_id).ok_or_else(Error::no_change)?;
        let id = id.strip_prefix("/change/").unwrap_or(id);
        let change = account.changes.get_mut(id).ok_or_else(Error::no_change)?;
        // The committed in-memory record view is already the published local DNS evidence.
        change.status = "INSYNC";
        Ok(Output::new(
            200,
            "GetChangeResponse",
            format!("<ChangeInfo>{}</ChangeInfo>", change_fields(change)),
        ))
    }
}

#[async_trait]
impl NativeHandler for Route53Service {
    async fn handle(&self, request: ServiceRequest) -> Response {
        match self.dispatch(&request) {
            Ok(output) => output.into_response(&request.request_id),
            Err(error) => error.into_response(&request.request_id),
        }
    }
}

pub fn register(registry: &Arc<ServiceRegistry>) -> Arc<Route53Service> {
    let service = Arc::new(Route53Service::new());
    registry.register_native(
        ServiceName::new("route53"),
        ServiceMetadata::new(AwsProtocol::RestXml, None),
        service.clone(),
    );
    service
}

fn find_zone<'a>(
    accounts: &'a BTreeMap<String, Account>,
    account: &str,
    id: &str,
) -> Result<&'a Zone, Error> {
    accounts
        .get(account)
        .and_then(|a| a.zones.get(zone_id(id)))
        .ok_or_else(Error::no_zone)
}

fn zone_id(id: &str) -> &str {
    id.strip_prefix("/hostedzone/").unwrap_or(id)
}

fn new_change(account: &mut Account) -> Change {
    account.next_change += 1;
    let id = format!("C{:013X}", account.next_change);
    let submitted_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let change = Change {
        id: id.clone(),
        submitted_at,
        status: "PENDING",
    };
    account.changes.insert(id, change.clone());
    change
}

fn default_records(name: &str) -> BTreeMap<RecordKey, Record> {
    let mut records = BTreeMap::new();
    let ns = Record {
        key: RecordKey {
            name: name.to_owned(),
            record_type: "NS".into(),
            identifier: None,
        },
        ttl: 172800,
        failover: None,
        health_check_id: None,
        values: vec![
            "ns-1.awsdns-local.test.".into(),
            "ns-2.awsdns-local.test.".into(),
            "ns-3.awsdns-local.test.".into(),
            "ns-4.awsdns-local.test.".into(),
        ],
    };
    let soa = Record {
        key: RecordKey {
            name: name.to_owned(),
            record_type: "SOA".into(),
            identifier: None,
        },
        ttl: 900,
        failover: None,
        health_check_id: None,
        values: vec![
            "ns-1.awsdns-local.test. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400".into(),
        ],
    };
    records.insert(ns.key.clone(), ns);
    records.insert(soa.key.clone(), soa);
    records
}

fn canonical_name(raw: &str) -> Result<String, Error> {
    let lower = raw.trim_end_matches('.').to_ascii_lowercase();
    if lower.is_empty()
        || lower.len() > 253
        || lower.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
    {
        return Err(Error::new("InvalidDomainName", 400, "Invalid DNS name"));
    }
    Ok(format!("{lower}."))
}

fn parse_record(node: &Node, zone: &str) -> Result<Record, Error> {
    node.only(&[
        "Name",
        "Type",
        "TTL",
        "ResourceRecords",
        "AliasTarget",
        "SetIdentifier",
        "Weight",
        "Region",
        "GeoLocation",
        "Failover",
        "MultiValueAnswer",
        "HealthCheckId",
        "CidrRoutingConfig",
    ])?;
    if node.children.iter().any(|child| {
        ![
            "Name",
            "Type",
            "TTL",
            "ResourceRecords",
            "SetIdentifier",
            "Failover",
            "HealthCheckId",
        ]
        .contains(&child.name.as_str())
    }) {
        return Err(Error::change(
            "Routing policies and aliases are not supported",
        ));
    }
    let name = canonical_name(node.required_value("Name")?)?;
    if name != zone && !name.ends_with(&format!(".{zone}")) {
        return Err(Error::change("Record name is outside hosted zone"));
    }
    let record_type = node.required_value("Type")?;
    if !["A", "AAAA", "CNAME", "TXT"].contains(&record_type) {
        return Err(Error::change("Unsupported record type"));
    }
    if record_type == "CNAME" && name == zone {
        return Err(Error::change("CNAME is not allowed at zone apex"));
    }
    let identifier = node.value("SetIdentifier")?.map(str::to_owned);
    let failover = node.value("Failover")?.map(str::to_owned);
    let health_check_id = node.value("HealthCheckId")?.map(str::to_owned);
    if let Some(ref failover) = failover {
        if !matches!(failover.as_str(), "PRIMARY" | "SECONDARY")
            || identifier
                .as_ref()
                .is_none_or(|id| id.is_empty() || id.len() > 128)
        {
            return Err(Error::change("Invalid failover record identity"));
        }
    } else if identifier.is_some() || health_check_id.is_some() {
        return Err(Error::change(
            "SetIdentifier and HealthCheckId require Failover",
        ));
    }
    if health_check_id.as_ref().is_some_and(|id| id.is_empty()) {
        return Err(Error::change("Invalid HealthCheckId"));
    }
    let ttl = node
        .required_value("TTL")?
        .parse::<u32>()
        .map_err(|_| Error::change("Invalid TTL"))?;
    let values_node = node.required("ResourceRecords")?;
    if values_node.children.is_empty() || values_node.children.len() > 1000 {
        return Err(Error::change("Invalid number of record values"));
    }
    let mut values = Vec::new();
    for value in &values_node.children {
        if value.name != "ResourceRecord" {
            return Err(Error::change("Invalid ResourceRecord"));
        }
        value.only(&["Value"])?;
        let text = value.required_value("Value")?;
        match record_type {
            "A" => {
                Ipv4Addr::from_str(text).map_err(|_| Error::change("Invalid IPv4 address"))?;
            }
            "AAAA" => {
                Ipv6Addr::from_str(text).map_err(|_| Error::change("Invalid IPv6 address"))?;
            }
            "CNAME" => {
                canonical_name(text)?;
            }
            "TXT" => {
                if text.len() < 2
                    || !text.starts_with('"')
                    || !text.ends_with('"')
                    || text.len() > 257
                {
                    return Err(Error::change(
                        "TXT value must be a quoted string of at most 255 bytes",
                    ));
                }
            }
            _ => unreachable!(),
        }
        values.push(text.to_owned());
    }
    Ok(Record {
        key: RecordKey {
            name,
            record_type: record_type.to_owned(),
            identifier,
        },
        ttl,
        values,
        failover,
        health_check_id,
    })
}

fn validate_failover(
    records: &BTreeMap<RecordKey, Record>,
    checks: &BTreeMap<String, HealthCheck>,
) -> Result<(), Error> {
    let mut groups: BTreeMap<(&str, &str), Vec<&Record>> = BTreeMap::new();
    for record in records.values() {
        if record
            .health_check_id
            .as_ref()
            .is_some_and(|id| !checks.contains_key(id))
        {
            return Err(Error::change("Health check does not exist"));
        }
        groups
            .entry((&record.key.name, &record.key.record_type))
            .or_default()
            .push(record);
    }
    for group in groups.values() {
        if group.iter().any(|r| r.failover.is_some())
            && (group.len() > 2
                || group.iter().any(|r| r.failover.is_none())
                || group
                    .iter()
                    .filter(|r| r.failover.as_deref() == Some("PRIMARY"))
                    .count()
                    > 1
                || group
                    .iter()
                    .filter(|r| r.failover.as_deref() == Some("SECONDARY"))
                    .count()
                    > 1)
        {
            return Err(Error::change(
                "Failover allows one PRIMARY and one SECONDARY",
            ));
        }
    }
    Ok(())
}

fn validate_cname_conflicts(
    records: &BTreeMap<RecordKey, Record>,
    apex: &str,
) -> Result<(), Error> {
    let mut names: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for key in records.keys() {
        names.entry(&key.name).or_default().insert(&key.record_type);
    }
    for (name, types) in names {
        if types.contains("CNAME") && (types.len() > 1 || name == apex) {
            return Err(Error::change("CNAME conflicts with another record"));
        }
    }
    Ok(())
}

fn reverse_labels(name: &str) -> String {
    name.trim_end_matches('.')
        .split('.')
        .rev()
        .collect::<Vec<_>>()
        .join(".")
        + "."
}

fn query_params(raw: Option<&str>) -> Result<BTreeMap<String, String>, Error> {
    let mut params = BTreeMap::new();
    if let Some(raw) = raw {
        for pair in raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            if params
                .insert(key.to_owned(), percent_decode(value)?)
                .is_some()
            {
                return Err(Error::invalid("Duplicate query parameter"));
            }
        }
    }
    Ok(params)
}

fn percent_decode(raw: &str) -> Result<String, Error> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut chars = raw.bytes();
    while let Some(byte) = chars.next() {
        if byte == b'%' {
            let a = chars
                .next()
                .ok_or_else(|| Error::invalid("Invalid URL encoding"))?;
            let b = chars
                .next()
                .ok_or_else(|| Error::invalid("Invalid URL encoding"))?;
            let hex = [a, b];
            let value = u8::from_str_radix(
                std::str::from_utf8(&hex).map_err(|_| Error::invalid("Invalid URL encoding"))?,
                16,
            )
            .map_err(|_| Error::invalid("Invalid URL encoding"))?;
            bytes.push(value);
        } else if byte == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).map_err(|_| Error::invalid("Invalid URL encoding"))
}

fn parse_max(value: Option<&String>, default: usize) -> Result<usize, Error> {
    match value {
        None => Ok(default),
        Some(value) => {
            let max = value
                .parse::<usize>()
                .map_err(|_| Error::invalid("Invalid MaxItems"))?;
            if !(1..=default).contains(&max) {
                return Err(Error::invalid("Invalid MaxItems"));
            }
            Ok(max)
        }
    }
}

fn health_check_fields(check: &HealthCheck) -> String {
    format!("<Id>{}</Id><CallerReference>{}</CallerReference><HealthCheckConfig><Type>RECOVERY_CONTROL</Type><RoutingControlArn>{}</RoutingControlArn></HealthCheckConfig>",
        escape(&check.id), escape(&check.caller_reference), escape(&check.routing_control_arn))
}

fn zone_fields(zone: &Zone) -> String {
    format!("<Id>/hostedzone/{}</Id><Name>{}</Name><CallerReference>{}</CallerReference><Config><Comment>{}</Comment><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>{}</ResourceRecordSetCount>",
        zone.id, escape(&zone.name), escape(&zone.caller_reference), escape(&zone.comment), zone.records.len())
}

fn delegation_set(_zone: &Zone) -> String {
    "<DelegationSet><NameServers><NameServer>ns-1.awsdns-local.test.</NameServer><NameServer>ns-2.awsdns-local.test.</NameServer><NameServer>ns-3.awsdns-local.test.</NameServer><NameServer>ns-4.awsdns-local.test.</NameServer></NameServers></DelegationSet>".into()
}

fn record_fields(record: &Record) -> String {
    let values = record
        .values
        .iter()
        .map(|value| {
            format!(
                "<ResourceRecord><Value>{}</Value></ResourceRecord>",
                escape(value)
            )
        })
        .collect::<String>();
    let identifier = record
        .key
        .identifier
        .as_ref()
        .map(|id| format!("<SetIdentifier>{}</SetIdentifier>", escape(id)))
        .unwrap_or_default();
    let failover = record
        .failover
        .as_ref()
        .map(|f| format!("<Failover>{f}</Failover>"))
        .unwrap_or_default();
    let health = record
        .health_check_id
        .as_ref()
        .map(|id| format!("<HealthCheckId>{}</HealthCheckId>", escape(id)))
        .unwrap_or_default();
    format!("<ResourceRecordSet><Name>{}</Name><Type>{}</Type>{identifier}{failover}<TTL>{}</TTL><ResourceRecords>{values}</ResourceRecords>{health}</ResourceRecordSet>",
        escape(&record.key.name), record.key.record_type, record.ttl)
}

fn change_fields(change: &Change) -> String {
    format!(
        "<Id>/change/{}</Id><Status>{}</Status><SubmittedAt>{}</SubmittedAt>",
        change.id, change.status, change.submitted_at
    )
}

fn escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

struct Output {
    status: u16,
    root: &'static str,
    body: String,
    headers: Vec<(&'static str, String)>,
}

impl Output {
    fn new(status: u16, root: &'static str, body: String) -> Self {
        Self {
            status,
            root,
            body,
            headers: Vec::new(),
        }
    }

    fn header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    fn into_response(self, request_id: &str) -> Response {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{} xmlns=\"{}\">{}</{}>",
            self.root, XMLNS, self.body, self.root
        );
        let mut builder = Response::builder()
            .status(self.status)
            .header(http::header::CONTENT_TYPE, "text/xml")
            .header("x-amzn-RequestId", request_id);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder
            .body(Body::from(body))
            .expect("valid Route 53 XML response")
    }
}

struct Error {
    code: &'static str,
    status: u16,
    message: &'static str,
}

impl Error {
    fn new(code: &'static str, status: u16, message: &'static str) -> Self {
        Self {
            code,
            status,
            message,
        }
    }
    fn invalid(message: &'static str) -> Self {
        Self::new("InvalidInput", 400, message)
    }
    fn change(message: &'static str) -> Self {
        Self::new("InvalidChangeBatch", 400, message)
    }
    fn no_zone() -> Self {
        Self::new("NoSuchHostedZone", 404, "Hosted zone does not exist")
    }
    fn no_health_check() -> Self {
        Self::new("NoSuchHealthCheck", 404, "Health check does not exist")
    }
    fn no_change() -> Self {
        Self::new("NoSuchChange", 404, "Change does not exist")
    }
    fn internal() -> Self {
        Self::new("InternalError", 500, "Route 53 store unavailable")
    }

    fn into_response(self, request_id: &str) -> Response {
        let body = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ErrorResponse xmlns=\"{}\"><Error><Type>Sender</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{}</RequestId></ErrorResponse>",
            XMLNS, self.code, self.message, escape(request_id));
        Response::builder()
            .status(self.status)
            .header(http::header::CONTENT_TYPE, "text/xml")
            .header("x-amzn-RequestId", request_id)
            .body(Body::from(body))
            .expect("valid Route 53 XML error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method, StatusCode, Uri};

    fn request(
        method: Method,
        path: &str,
        account: &str,
        region: &str,
        body: &str,
    ) -> ServiceRequest {
        ServiceRequest {
            method,
            uri: path.parse::<Uri>().unwrap(),
            headers: HeaderMap::new(),
            body: body.to_owned().into(),
            region: region.into(),
            account_id: account.into(),
            request_id: "route53-test".into(),
        }
    }

    async fn call(service: &Route53Service, request: ServiceRequest) -> (StatusCode, String) {
        let response = service.handle(request).await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn create_xml() -> String {
        format!("<CreateHostedZoneRequest xmlns=\"{XMLNS}\"><Name>example.test</Name><CallerReference>ref-one</CallerReference></CreateHostedZoneRequest>")
    }

    fn change_xml(items: &str) -> String {
        format!("<ChangeResourceRecordSetsRequest xmlns=\"{XMLNS}\"><ChangeBatch><Changes>{items}</Changes></ChangeBatch></ChangeResourceRecordSetsRequest>")
    }

    fn item(action: &str, name: &str, kind: &str, value: &str) -> String {
        format!("<Change><Action>{action}</Action><ResourceRecordSet><Name>{name}</Name><Type>{kind}</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>{value}</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change>")
    }

    #[tokio::test]
    async fn recovery_controls_switch_failover_records_without_crossing_accounts() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let service = Route53Service::new();
        let active = Arc::new(AtomicBool::new(true));
        let state = active.clone();
        service.set_routing_control_resolver(Arc::new(move |arn| {
            if arn.ends_with("primary") {
                Some(state.load(Ordering::SeqCst))
            } else if arn.ends_with("secondary") {
                Some(true)
            } else {
                None
            }
        }));
        call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/hostedzone",
                "123456789012",
                "us-east-1",
                &create_xml(),
            ),
        )
        .await;
        for (caller, arn) in [
            (
                "primary",
                "arn:aws:route53-recovery-control::123456789012:controlpanel/panel/routingcontrol/primary",
            ),
            (
                "secondary",
                "arn:aws:route53-recovery-control::123456789012:controlpanel/panel/routingcontrol/secondary",
            ),
        ] {
            let body = format!("<CreateHealthCheckRequest xmlns=\"{XMLNS}\"><CallerReference>{caller}</CallerReference><HealthCheckConfig><Type>RECOVERY_CONTROL</Type><RoutingControlArn>{arn}</RoutingControlArn></HealthCheckConfig></CreateHealthCheckRequest>");
            let (status, _) = call(
                &service,
                request(
                    Method::POST,
                    "/2013-04-01/healthcheck",
                    "123456789012",
                    "us-east-1",
                    &body,
                ),
            )
            .await;
            assert_eq!(status, StatusCode::CREATED);
        }
        let cross_account = format!("<CreateHealthCheckRequest xmlns=\"{XMLNS}\"><CallerReference>cross</CallerReference><HealthCheckConfig><Type>RECOVERY_CONTROL</Type><RoutingControlArn>arn:aws:route53-recovery-control::123456789012:controlpanel/panel/routingcontrol/primary</RoutingControlArn></HealthCheckConfig></CreateHealthCheckRequest>");
        let (status, _) = call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/healthcheck",
                "other-account",
                "us-east-1",
                &cross_account,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let unknown = format!("<CreateHealthCheckRequest xmlns=\"{XMLNS}\"><CallerReference>unknown</CallerReference><HealthCheckConfig><Type>RECOVERY_CONTROL</Type><RoutingControlArn>arn:aws:route53-recovery-control::123456789012:controlpanel/panel/routingcontrol/missing</RoutingControlArn></HealthCheckConfig></CreateHealthCheckRequest>");
        let (status, body) = call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/healthcheck",
                "123456789012",
                "us-east-1",
                &unknown,
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("<Code>InvalidInput</Code>"));
        let zone = "/2013-04-01/hostedzone/Z0000000000001/rrset";
        for (role, id, check, value) in [
            (
                "PRIMARY",
                "east",
                "00000001-0000-4000-8000-000000000001",
                "192.0.2.1",
            ),
            (
                "SECONDARY",
                "west",
                "00000002-0000-4000-8000-000000000002",
                "192.0.2.2",
            ),
        ] {
            let item = format!("<Change><Action>CREATE</Action><ResourceRecordSet><Name>app.example.test.</Name><Type>A</Type><SetIdentifier>{id}</SetIdentifier><Failover>{role}</Failover><TTL>0</TTL><ResourceRecords><ResourceRecord><Value>{value}</Value></ResourceRecord></ResourceRecords><HealthCheckId>{check}</HealthCheckId></ResourceRecordSet></Change>");
            let (status, _) = call(
                &service,
                request(
                    Method::POST,
                    zone,
                    "123456789012",
                    "us-east-1",
                    &change_xml(&item),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        assert_eq!(
            service.resolve_records("123456789012", "app.example.test", "A"),
            vec!["192.0.2.1"]
        );
        assert_eq!(
            service.resolve_records("123456789012", "app.example.test", "A"),
            vec!["192.0.2.1"]
        );
        active.store(false, Ordering::SeqCst);
        assert_eq!(
            service.resolve_records("123456789012", "app.example.test", "A"),
            vec!["192.0.2.2"]
        );
        assert!(service
            .resolve_records("b", "app.example.test", "A")
            .is_empty());
        let (status, _) = call(
            &service,
            request(
                Method::DELETE,
                "/2013-04-01/healthcheck/00000001-0000-4000-8000-000000000001",
                "123456789012",
                "us-east-1",
                "",
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn whole_batch_failure_preserves_records_and_change_count() {
        let service = Route53Service::new();
        let (status, _) = call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/hostedzone",
                "a",
                "us-east-1",
                &create_xml(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let zone = "/2013-04-01/hostedzone/Z0000000000001/rrset/";
        let good = item("CREATE", "one.example.test.", "A", "192.0.2.5");
        let bad = item("CREATE", "two.example.test.", "A", "not-an-ip");
        let (status, body) = call(
            &service,
            request(
                Method::POST,
                zone,
                "a",
                "us-east-1",
                &change_xml(&(good + &bad)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("<Code>InvalidChangeBatch</Code>"));
        let (_, body) = call(&service, request(Method::GET, zone, "a", "us-west-2", "")).await;
        assert!(!body.contains("one.example.test."));
        assert!(!body.contains("two.example.test."));
        assert_eq!(
            service.resolve_records("a", "one.example.test", "A"),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn acm_dns_evidence_reads_only_committed_txt_in_account() {
        let service = Route53Service::new();
        call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/hostedzone",
                "a",
                "us-east-1",
                &create_xml(),
            ),
        )
        .await;
        let path = "/2013-04-01/hostedzone/Z0000000000001/rrset/";
        let txt = item(
            "CREATE",
            "_acme-challenge.example.test.",
            "TXT",
            "\"proof\"",
        );
        let (status, _) = call(
            &service,
            request(Method::POST, path, "a", "us-east-1", &change_xml(&txt)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            service.resolve_records("a", "_acme-challenge.example.test.", "TXT"),
            vec!["\"proof\""]
        );
        assert!(service
            .resolve_records("b", "_acme-challenge.example.test.", "TXT")
            .is_empty());
    }

    #[tokio::test]
    async fn account_global_scope_and_exact_delete() {
        let service = Route53Service::new();
        call(
            &service,
            request(
                Method::POST,
                "/2013-04-01/hostedzone",
                "a",
                "us-east-1",
                &create_xml(),
            ),
        )
        .await;
        let zone = "/2013-04-01/hostedzone/Z0000000000001";
        let (_, body) = call(&service, request(Method::GET, zone, "a", "eu-west-1", "")).await;
        assert!(body.contains("<Name>example.test.</Name>"));
        let (status, _) = call(&service, request(Method::GET, zone, "b", "us-east-1", "")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let change_path = format!("{zone}/rrset/");
        let record = item("CREATE", "www.example.test.", "AAAA", "2001:db8::1");
        let (status, _) = call(
            &service,
            request(
                Method::POST,
                &change_path,
                "a",
                "us-west-2",
                &change_xml(&record),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            service.resolve_records("a", "www.example.test", "AAAA"),
            vec!["2001:db8::1"]
        );
        assert!(service
            .resolve_records("b", "www.example.test", "AAAA")
            .is_empty());
        let (status, body) = call(
            &service,
            request(Method::DELETE, zone, "a", "us-east-1", ""),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("<Code>HostedZoneNotEmpty</Code>"));
        let delete = item("DELETE", "www.example.test.", "AAAA", "2001:db8::1");
        let (status, _) = call(
            &service,
            request(
                Method::POST,
                &change_path,
                "a",
                "us-east-1",
                &change_xml(&delete),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &service,
            request(Method::DELETE, zone, "a", "us-east-1", ""),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
