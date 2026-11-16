//! Lambda and ECS share the same bounded, live EC2 DNS policy.
pub(crate) use locallycloud_ec2::guest_dns::{serve_local_endpoint, system_resolver, VpcDnsScope};
