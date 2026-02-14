//! Dependency manager — install, lifecycle, and health check for external deps.
//!
//! Components declare needs via `HasDependencies` trait. `DepManager` handles
//! download, install, start, health check, and stop.

pub mod fetcher;
pub mod manager;
pub mod registry;
pub mod types;

pub use manager::DepManager;
pub use types::{DepKind, Dependency, HasDependencies, HealthCheck};
