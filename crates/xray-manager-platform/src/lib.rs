//! Platform adapters and runtime backend selection.

pub mod artifacts;
pub mod fake;
#[cfg(target_os = "linux")]
pub mod linux;
pub mod portable;
pub mod registry;
pub mod templates;
pub mod unsupported;

pub use registry::{BackendFactory, BackendRegistry};
