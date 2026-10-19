//! Lambda and ECS share the same bounded, live EC2 DNS policy.
pub(crate) use locallycloud_ec2::guest_dns::{serve, system_resolver};
