//! Core services that make up a TACEO:OPRF node.
//!
//! This module exposes all internal services used by the node to handle
//! cryptography, chain interactions, OPRF sessions, and session storage.
//! Each service is designed to encapsulate a specific
//! responsibility and can be used by higher-level components such as the API
//! or the main application state.
//!
//! # Services overview
//!
//! - [`key_event_watcher`] – watches the blockchain for key-generation events.
//! - [`open_sessions`] – bookkeeping of all open session-ids to prevent session-id re-usage.
//! - [`oprf_key_material_store`] – provides a store that securely holds all OPRF key-material.
//! - [`secret_manager`] – stores and retrieves secrets.

pub(crate) mod key_event_watcher;
pub(crate) mod open_sessions;
pub mod oprf_key_material_store;
pub mod secret_manager;
