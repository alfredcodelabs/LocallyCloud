//! locallycloud compute layer.
//!
//! Defines the [`runtime`] `ComputeRuntime` trait abstracting workload execution
//! and its backends:
//! - [`firecracker`]: primary backend driving Firecracker microVMs via `/dev/kvm`
//! - [`youki`]: daemonless OCI fallback (`youki` / `crun`) when KVM is unavailable
//! - [`selector`]: chooses a backend from host capabilities and config
//!
//! Docker, the Docker daemon and `bollard` are explicitly excluded.
//! Each module is currently a skeleton; behavior is filled in by the core
//! implementation tasks.

pub mod firecracker;
mod netns_socket;
pub mod private_dir;
pub mod runtime;
pub mod selector;
pub mod youki;
