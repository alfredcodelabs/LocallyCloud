//! locallycloud compute layer.
//!
//! Defines the [`runtime`] `ComputeRuntime` trait abstracting workload execution and its
//! backend, [`youki`]: rootless, daemonless OCI (`crun`, then `youki`, from `PATH`).
//!
//! Docker, the Docker daemon and `bollard` are explicitly excluded.
//! Each module is currently a skeleton; behavior is filled in by the core
//! implementation tasks.

mod netns_socket;
mod output;
pub mod private_dir;
pub mod runtime;
pub mod youki;

mod youki_setup;
