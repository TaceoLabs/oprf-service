//! Core services that make up a TACEO:Oprf node.
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

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use parking_lot::Mutex;

pub(crate) mod key_event_watcher;
pub(crate) mod open_sessions;
pub mod oprf_key_material_store;
pub mod secret_manager;

/// A struct that keeps track of the health of all async services started by the service.
///
/// Relevant for the `/health` route. Implementations should call [`StartedServices::new_service`] for their services and set the bool to `true` if the service started successfully.
#[derive(Debug, Clone, Default)]
pub struct StartedServices {
    key_event_watcher: Arc<AtomicBool>,
    external_service: Arc<Mutex<Vec<Arc<AtomicBool>>>>,
}

impl StartedServices {
    /// Initializes all services as not started.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a new external service to the bookkeeping struct.
    ///
    /// Implementations should call this method for every async task that they start. The returned `AtomicBool` should then be set to `true` if the service is ready.
    pub fn new_service(&mut self) -> Arc<AtomicBool> {
        let service = Arc::new(AtomicBool::default());
        self.external_service.lock().push(Arc::clone(&service));
        service
    }

    /// Returns `true` if all services did start at the time of calling.
    ///
    /// This method simply loads all flags sequentially without using a lock, which means potentially during this call a service's state changes. We do not care about this case, as we only go from `false` to `true` anyways and in worst-case someone needs to call `/health` once more.
    pub(crate) fn all_started(&self) -> bool {
        self.key_event_watcher.load(Ordering::Relaxed)
            && self
                .external_service
                .lock()
                .iter()
                .all(|service| service.load(Ordering::Relaxed))
    }
}
