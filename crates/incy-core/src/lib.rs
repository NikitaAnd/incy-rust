//! INCY's platform-independent Rust client core.
//!
//! This crate owns parsing, validation, configuration generation, local storage
//! and the Xray process. GUI code does not construct JSON or manipulate keys.
//! Xray-core remains the data plane; this is not a new proxy protocol stack.

pub mod config;
pub mod error;
pub mod model;
pub mod runtime;
pub mod share_link;
pub mod store;
pub mod subscription;
pub mod system_proxy;
pub mod tun;

pub use error::{Error, Result};
pub use model::{AppState, Endpoint, Language, Profile, Protocol, Routing, Security, Settings, Theme};
pub use store::Store;
