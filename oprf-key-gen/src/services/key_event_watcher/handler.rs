use std::num::NonZeroU16;

use alloy::{primitives::TxHash, providers::DynProvider};
use eyre::Context;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    chain::{
        OprfKeyGen::Round2Contribution,
        OprfKeyRegistry::{self, OprfKeyRegistryInstance, WrongRound},
    },
    crypto::{EphemeralEncryptionPublicKey, OprfPublicKey, SecretGenCiphertext},
};

use crate::metrics;
use crate::services::{
    key_event_watcher::{KeyRegistryEvent, KeyRegistryEventError},
    secret_gen::{Contributions, DLogSecretGenService},
    transaction_handler::TransactionHandler,
};

use super::Result;

/// Dispatches decoded [`KeyRegistryEvent`]s to the appropriate protocol-round handler.
pub(super) struct KeyRegistryEventHandler {
    contract: OprfKeyRegistryInstance<DynProvider>,
    secret_gen: DLogSecretGenService,
    threshold: NonZeroU16,
    tx: TransactionHandler,
}

impl KeyRegistryEventHandler {
    /// Construct a new handler.
    ///
    /// # Arguments
    ///
    /// * `contract` - A connected `OprfKeyRegistry` instance used for view calls (public-key
    ///   fetches) and round submissions.
    /// * `secret_gen` - Manages local key-gen intermediates and computes contributions.
    /// * `threshold` - MPC threshold forwarded to round-1 calls.
    /// * `tx` - Submits contribution transactions and waits for confirmations.
    pub(super) fn new(
        contract: OprfKeyRegistryInstance<DynProvider>,
        secret_gen: DLogSecretGenService,
        threshold: NonZeroU16,
        tx: TransactionHandler,
    ) -> Self {
        Self {
            contract,
            secret_gen,
            threshold,
            tx,
        }
    }

    /// Dispatch a decoded event to the appropriate protocol-round handler.
    pub(super) async fn handle(
        &self,
        event: KeyRegistryEvent,
        event_span: &tracing::Span,
    ) -> Result<()> {
        match event {
            KeyRegistryEvent::KeyGenRound1 { key_id } => {
                self.keygen_round1(key_id, event_span).await
            }
            KeyRegistryEvent::Round2 { key_id, epoch } => {
                self.round2(key_id, epoch, event_span).await
            }
            KeyRegistryEvent::Round3 {
                key_id,
                epoch,
                contributions,
            } => self.round3(key_id, epoch, contributions, event_span).await,
            KeyRegistryEvent::Finalize { key_id, epoch } => self.finalize(key_id, epoch).await,
            KeyRegistryEvent::ReshareRound1 { key_id, epoch } => {
                self.reshare_round1(key_id, epoch, event_span).await
            }
            KeyRegistryEvent::Delete { key_id } => self.delete(key_id).await,
            KeyRegistryEvent::Abort { key_id } => self.abort(key_id).await,
            KeyRegistryEvent::NotEnoughProducers { key_id } => {
                // we simply log an error to trigger a page
                tracing::error!("Received not-enough-producers for {key_id:?}");
                metrics::chain_events::inc_not_enough_producers();
                Ok(())
            }
            KeyRegistryEvent::Unknown => {
                tracing::warn!("cannot handle unknown event - ignoring");
                Ok(())
            }
        }
    }

    async fn keygen_round1(
        &self,
        oprf_key_id: OprfKeyId,
        event_span: &tracing::Span,
    ) -> Result<()> {
        tracing::trace!("Received KeyGenRound1 event");
        let contribution = self
            .secret_gen
            .key_gen_round1(oprf_key_id, ShareEpoch::default(), self.threshold)
            .await?;
        tracing::trace!("finished round1 - now reporting to chain..");
        let tx_hash = self
            .tx
            .add_round1_keygen_contribution(oprf_key_id, contribution)
            .await?;

        record_tx_hash(tx_hash, event_span);
        metrics::chain_events::inc_keygen_round1();
        tracing::info!("Finished key-gen 1 for {oprf_key_id}");
        Ok(())
    }

    async fn round2(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        event_span: &tracing::Span,
    ) -> Result<()> {
        tracing::trace!("Received SecretGenRound2 event");
        let nodes = self.fetch_producer_public_keys(oprf_key_id).await?;
        if nodes.is_empty() {
            metrics::chain_events::inc_consumer();
            tracing::info!("Finished round 2 for {oprf_key_id} and epoch {epoch} as producer");
        } else {
            let contribution = self
                .secret_gen
                .producer_round2(oprf_key_id, epoch, nodes)
                .await?;
            tracing::trace!("finished round 2 - now reporting");
            let contribution = Round2Contribution::from(contribution);
            let tx_hash = self
                .tx
                .add_round2_contribution(oprf_key_id, contribution)
                .await?;
            record_tx_hash(tx_hash, event_span);
            metrics::chain_events::inc_producer();
            tracing::info!("Finished round 2 for {oprf_key_id} and epoch {epoch} as producer");
        }
        metrics::chain_events::inc_round2();
        Ok(())
    }

    async fn round3(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        contributions: Contributions,
        event_span: &tracing::Span,
    ) -> Result<()> {
        tracing::trace!("Round 3 event for {oprf_key_id} with epoch {epoch}");
        let (ciphers, pks) = tokio::join!(
            self.fetch_round2_ciphers(oprf_key_id),
            self.fetch_consumer_public_keys(oprf_key_id)
        );
        self.secret_gen
            .round3(oprf_key_id, epoch, ciphers?, contributions, &pks?)
            .await?;
        tracing::trace!("finished round 3 - now reporting");
        let tx_hash = self.tx.add_round3_contribution(oprf_key_id).await?;
        record_tx_hash(tx_hash, event_span);
        metrics::chain_events::inc_round3();
        tracing::info!("Finished round 3 for {oprf_key_id} and epoch {epoch} as producer");

        Ok(())
    }

    async fn finalize(&self, oprf_key_id: OprfKeyId, epoch: ShareEpoch) -> Result<()> {
        tracing::trace!("Finalize event for {oprf_key_id} with epoch {epoch}");
        let oprf_public_key = self.fetch_oprf_public_key(oprf_key_id).await?;
        if let Some(oprf_public_key) = oprf_public_key {
            self.secret_gen
                .finalize(oprf_key_id, epoch, oprf_public_key)
                .await?;
            tracing::info!("Finished finalize for {oprf_key_id:?} with epoch {epoch}");
        } else {
            tracing::info!("Received finalize on deleted key - continue and mark as done");
        }
        metrics::chain_events::inc_finalize();
        Ok(())
    }

    async fn reshare_round1(
        &self,
        oprf_key_id: OprfKeyId,
        epoch: ShareEpoch,
        event_span: &tracing::Span,
    ) -> Result<()> {
        tracing::trace!("Received ReshareRound1 event");
        let contribution = self
            .secret_gen
            .reshare_round1(oprf_key_id, epoch, self.threshold)
            .await?;
        let tx_hash = self
            .tx
            .add_round1_reshare_contribution(oprf_key_id, contribution)
            .await?;
        record_tx_hash(tx_hash, event_span);
        metrics::chain_events::inc_reshare_round1();
        tracing::info!("Finished reshare round 1 for {oprf_key_id:?} with epoch {epoch}");
        Ok(())
    }

    async fn delete(&self, oprf_key_id: OprfKeyId) -> Result<()> {
        tracing::trace!("Received Delete event for {oprf_key_id}");
        // Delete finalized shares and any associated in-progress state for this key.
        self.secret_gen
            .delete_oprf_key_material(oprf_key_id)
            .await?;
        metrics::chain_events::inc_delete();
        tracing::info!("successfully deleted {oprf_key_id:?}");
        Ok(())
    }

    async fn abort(&self, oprf_key_id: OprfKeyId) -> Result<()> {
        // In contrast to delete, abort only removes in-progress state and keeps finalized shares.
        self.secret_gen.abort_keygen(oprf_key_id).await?;
        metrics::chain_events::inc_abort();
        tracing::info!("successfully aborted {oprf_key_id:?}");
        Ok(())
    }

    // ================== HELPER FUNCTIONS ==================

    /// Calls `OprfKeyRegistry::loadPeerPublicKeysForProducers` and parses the result.
    ///
    /// Returns an empty `Vec` if the contract responds with `WrongRound`, which signals that
    /// this node is a consumer and the contract has already advanced past the producer phase.
    async fn fetch_producer_public_keys(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<Vec<EphemeralEncryptionPublicKey>> {
        tracing::trace!("fetching ephemeral public keys from chain..");
        let nodes = self
            .contract
            .loadPeerPublicKeysForProducers(oprf_key_id.into_inner())
            .call()
            .await;
        // Handle this separately because consumers can legitimately hit `WrongRound` here after
        // producers have already advanced the contract state.
        let nodes = match nodes {
            Ok(nodes) => nodes,
            Err(err) => {
                if let Some(WrongRound(round)) =
                    err.as_decoded_error::<OprfKeyRegistry::WrongRound>()
                {
                    tracing::trace!("reshare is already in round: {round} - we were a consumer");
                    // An empty producer list signals the consumer path below.
                    Vec::new()
                } else {
                    Err(err)?
                }
            }
        };
        let nodes = nodes
            .into_iter()
            .map(EphemeralEncryptionPublicKey::try_from)
            .collect::<eyre::Result<Vec<_>>>()?;
        Ok(nodes)
    }

    /// Calls `OprfKeyRegistry::getOprfPublicKey` and parses the result.
    ///
    /// Returns `None` if the contract responds with `DeletedId`, indicating the key was removed
    /// between event emission and handling; the caller should no-op in that case.
    async fn fetch_oprf_public_key(&self, oprf_key_id: OprfKeyId) -> Result<Option<OprfPublicKey>> {
        tracing::trace!("fetching oprf public key from chain");
        let oprf_public_key = match self
            .contract
            .getOprfPublicKey(oprf_key_id.into_inner())
            .call()
            .await
        {
            Ok(oprf_public_key) => oprf_public_key,
            Err(err) => {
                if let Some(OprfKeyRegistry::DeletedId { id: _ }) =
                    err.as_decoded_error::<OprfKeyRegistry::DeletedId>()
                {
                    tracing::info!(
                        "Key got deleted in the meantime - we ignore this key for now. Nodes will run into an error, but they will be fine"
                    );
                    return Ok(None);
                }
                return Err(KeyRegistryEventError::from(err));
            }
        };
        Ok(Some(OprfPublicKey::new(
            ark_babyjubjub::EdwardsAffine::try_from(oprf_public_key)?,
        )))
    }

    async fn fetch_round2_ciphers(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<Vec<SecretGenCiphertext>> {
        tracing::trace!("reading ciphers from chain..");
        let ciphers = self
            .contract
            .checkIsParticipantAndReturnRound2Ciphers(oprf_key_id.into_inner())
            .call()
            .await?;

        tracing::trace!("got ciphers from chain {} - parsing..", ciphers.len());
        Ok(ciphers
            .into_iter()
            .map(SecretGenCiphertext::try_from)
            .collect::<eyre::Result<Vec<_>>>()
            .context("while parsing round 2 ciphers")?)
    }

    async fn fetch_consumer_public_keys(
        &self,
        oprf_key_id: OprfKeyId,
    ) -> Result<Vec<EphemeralEncryptionPublicKey>> {
        tracing::trace!("getting the public keys from the producers...");
        let pks = self
            .contract
            .loadPeerPublicKeysForConsumers(oprf_key_id.into_inner())
            .call()
            .await?;

        Ok(pks
            .into_iter()
            .map(EphemeralEncryptionPublicKey::try_from)
            .collect::<eyre::Result<Vec<_>>>()
            .context("while parsing consumer public keys")?)
    }
}

#[inline]
fn record_tx_hash(tx_hash: TxHash, span: &tracing::Span) {
    span.record("tx_hash", tx_hash.to_string());
}
