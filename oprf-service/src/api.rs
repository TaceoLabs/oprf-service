//! API module for the OPRF node service.
//!
//! This module defines all HTTP endpoints an OPRF node must serve to participate in TACEO:Oprf and organizes them into submodules:
//!
//! - [`errors`] – Defines API error types and conversions from internal service errors.
//! - [`health`] – Provides health endpoints (`/health`).
//! - [`info`] – Info about the service (`/version`, `/wallet` and `/oprf_pub/{id}`).
//! - [`oprf`] – The implementation of the OPRF WebSocket endpoint `/oprf`.

pub(crate) mod errors;
pub(crate) mod health;
pub(crate) mod info;
pub(crate) mod oprf;
