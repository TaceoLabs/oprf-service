#![deny(missing_docs)]
#![deny(clippy::all, clippy::pedantic)]
#![deny(
    clippy::allow_attributes_without_reason,
    clippy::assertions_on_result_states,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::iter_over_hash_type,
    clippy::let_underscore_must_use,
    clippy::missing_assert_message,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::undocumented_unsafe_blocks,
    clippy::unnecessary_safety_comment,
    clippy::unwrap_used
)]
//! # TACEO:OPRF Umbrella Crate
//!
//! `taceo-oprf` bundles all TACEO:OPRF sub-crates into a single crate
//! so you can include only the features you need, without importing
//! each crate separately.
//!
//! ## Modules
//!
//! - [`client`] – high-level OPRF client functionality (requires the `client` feature).
//! - [`core`] – core OPRF primitives and cryptography (requires the `core` feature).
//! - [`dev_client`] – developer-focused client utilities for testing and mocking
//!   (requires the `dev-client` feature, implies `client`).
//! - [`service`] – OPRF service nodes, background tasks, and orchestration
//!   (requires the `service` feature).
//! - [`types`] – shared types and structs across OPRF crates
//!   (requires the `types` feature).
//!
//! ## Features
//!
//! Each module is optional. Enable only the modules you need to reduce
//! compile time and dependencies.
//!
//! ```toml
//! [dependencies]
//! taceo-oprf = { version = "0.7.1", features = ["client", "core"] }
//! ```
//!
//! The default feature `full` enables all modules.
//!
//! ## Example
//!
//! ```rust
//! #[cfg(feature = "client")]
//! use taceo_oprf::client::OprfClient;
//!
//! #[cfg(feature = "core")]
//! use taceo_oprf::core::OprfCore;
//!
//! // Use OprfClient or OprfCore depending on your feature flags
//! ```

#[cfg(feature = "client")]
/// Re-export of the `taceo-oprf-client` crate.
pub mod client {
    pub use oprf_client::*;
}

#[cfg(feature = "core")]
/// Re-export of the `taceo-oprf-core` crate.
pub mod core {
    pub use oprf_core::*;
}

#[cfg(feature = "dev-client")]
/// Re-export of the `taceo-oprf-dev-client` crate.
/// Requires the `client` feature.
pub mod dev_client {
    pub use oprf_dev_client::*;
}

#[cfg(feature = "service")]
/// Re-export of the `taceo-oprf-service` crate.
pub mod service {
    pub use oprf_service::*;
}

#[cfg(feature = "types")]
/// Re-export of the `taceo-oprf-types` crate.
pub mod types {
    pub use oprf_types::*;
}
