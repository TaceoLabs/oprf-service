//! Users are not allowed to use the same session-id over multiple requests because we use it as domain-separator for the Two-Nonce combiner hash (inspired by FROST2).
//!
//! Therefore, on a new request, we insert the session-id into [`OpenSessions`].

use std::{collections::HashSet, sync::Arc};

use parking_lot::Mutex;
use uuid::Uuid;

use crate::api::errors::Error;
use crate::metrics::METRICS_ID_NODE_SESSIONS_OPEN;

/// Keeps track of all currently opened sessions.
#[derive(Default, Clone)]
pub(crate) struct OpenSessions(Arc<Mutex<HashSet<Uuid>>>);

/// A guard for an open session.
///
/// As long as this guard exists, not other request can use the session id wrapped in this guard. On drop, marks the session as usable again.
#[must_use]
pub(crate) struct SessionDropGuard {
    session: Uuid,
    open_sessions: OpenSessions,
}

impl Drop for SessionDropGuard {
    fn drop(&mut self) {
        self.open_sessions.remove_session(self.session);
    }
}

impl OpenSessions {
    /// Inserts a new session into the service.
    ///
    /// If there is already a session with this id, will return an [`Error::SessionReuse`].
    ///
    /// On success, returns a [`SessionDropGuard`] that marks the session as reserved.
    pub(crate) fn insert_new_session(&self, session: Uuid) -> Result<SessionDropGuard, Error> {
        if self.0.lock().insert(session) {
            ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).increment(1);
            Ok(SessionDropGuard {
                session,
                open_sessions: self.clone(),
            })
        } else {
            Err(Error::SessionReuse(session))
        }
    }

    /// Removes a session.
    ///
    /// Is private so only the `Drop` implementation can call this.
    fn remove_session(&self, session: Uuid) {
        self.0.lock().remove(&session);
        ::metrics::gauge!(METRICS_ID_NODE_SESSIONS_OPEN).decrement(1);
    }
}
