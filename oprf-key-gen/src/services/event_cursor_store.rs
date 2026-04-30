//! Chain event cursor persistence for the OPRF key-gen service.
//!
//! This module defines the [`ChainCursorStorage`] trait, which is used to
//! durably persist and retrieve the `(block, log_index)` position up to which
//! the `key_event_watcher` service has processed on-chain events.
//! On startup the watcher loads this cursor and resumes backfill from that point,
//! ensuring no key-generation events are missed across restarts.
//!
//! Implementations must enforce monotonicity: storing a cursor that would roll back
//! an already-persisted position should be a no-op (the [`crate::postgres::PostgresDb`]
//! implementation logs a warning and silently discards such updates).
//!
//! Current [`ChainCursorStorage`] implementations:
//! - Postgres

use std::sync::Arc;

use async_trait::async_trait;
use nodes_common::web3::event_stream::ChainCursor;

/// A thread-safe, dynamically-dispatched [`ChainCursorStorage`].
pub type ChainCursorService = Arc<dyn ChainCursorStorage + Send + Sync>;

/// Persistent storage for the chain event cursor.
#[async_trait]
pub trait ChainCursorStorage {
    /// Returns the last durably stored `(block, log_index)` cursor.
    ///
    /// Returns `(0, 0)` if no cursor has been stored yet, causing the watcher to
    /// backfill from genesis.
    async fn load_chain_cursor(&self) -> eyre::Result<ChainCursor>;

    /// Persists the given cursor.
    ///
    /// Implementations must ignore updates that would move the cursor backwards.
    async fn store_chain_cursor(&self, chain_cursor: ChainCursor) -> eyre::Result<()>;
}
