//! Platform-independent domain and application services for xray-manager.

pub mod application;
pub mod config;
pub mod domain;
pub mod dto;
pub mod error;
pub mod events;
pub mod generation;
pub mod ports;
pub mod probe;
pub mod protocols;
pub mod render;
pub mod routing;
pub mod subscription;

pub use application::{ManagerService, Operation, OperationOptions, Query};
pub use error::{ManagerError, Result};
