//! Core services that make up TACEO:Oprf key-gen instance.
//!
//! This module exposes all internal services used by the node to handle
//! cryptography, chain interactions and secret generation.
//! Each service is designed to encapsulate a specific
//! responsibility and can be used by higher-level components such as the API
//! or the main application state.
//!
//! # Services overview
//!
//! - [`key_event_watcher`] – watches the blockchain for key-generation events.
//! - [`secret_gen`] – handles multi-round secret generation protocols.
//! - [`secret_manager`] – stores and retrieves secrets.
pub(crate) mod key_event_watcher;
pub(crate) mod secret_gen;
pub mod secret_manager;
pub(crate) mod transaction_nonce_store;
