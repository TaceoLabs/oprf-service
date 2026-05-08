use alloy::{primitives::LogData, rpc::types::Log, sol_types::SolEvent as _};
use eyre::Context as _;
use oprf_types::chain::OprfKeyRegistry;
use oprf_types::{OprfKeyId, ShareEpoch};

use crate::services::secret_gen::Contributions;

/// Typed representation of a decoded `OprfKeyRegistry` log.
///
/// Constructed exclusively via [`KeyRegistryEvent::try_decode_log`].
pub(super) enum KeyRegistryEvent {
    KeyGenRound1 {
        key_id: OprfKeyId,
    },
    Round2 {
        key_id: OprfKeyId,
        epoch: ShareEpoch,
    },
    Round3 {
        key_id: OprfKeyId,
        epoch: ShareEpoch,
        contributions: Contributions,
    },
    Finalize {
        key_id: OprfKeyId,
        epoch: ShareEpoch,
    },
    ReshareRound1 {
        key_id: OprfKeyId,
        epoch: ShareEpoch,
    },
    Delete {
        key_id: OprfKeyId,
    },
    Abort {
        key_id: OprfKeyId,
    },
    NotEnoughProducers {
        key_id: OprfKeyId,
    },
    Unknown,
}

impl KeyRegistryEvent {
    /// Decode a raw chain log into a typed [`KeyRegistryEvent`].
    ///
    /// Dispatches on `topic0` (the event signature hash).  Returns `Self::Unknown` for any
    /// unrecognised topic rather than erroring, so the watcher can skip irrelevant events.
    ///
    /// # Errors
    ///
    /// Returns an error if the ABI fields cannot be decoded (malformed log data) or if
    /// a `ReshareRound3` log contains a Lagrange coefficient that cannot be parsed as a
    /// `BabyJubJub` scalar.
    pub(super) fn try_decode_log(log: &Log<LogData>) -> eyre::Result<Self> {
        macro_rules! decode {
            () => {
                log.log_decode()
                    .context("while decoding log-event")?
                    .inner
                    .data
            };
        }
        tracing::trace!("trying to decode log...");
        let event = match log.topic0() {
            Some(&OprfKeyRegistry::SecretGenRound1::SIGNATURE_HASH) => {
                let OprfKeyRegistry::SecretGenRound1 { oprfKeyId, .. } = decode!();

                Self::KeyGenRound1 {
                    key_id: OprfKeyId::from(oprfKeyId),
                }
            }
            Some(&OprfKeyRegistry::SecretGenRound2::SIGNATURE_HASH) => {
                let OprfKeyRegistry::SecretGenRound2 { oprfKeyId, epoch } = decode!();
                Self::Round2 {
                    key_id: OprfKeyId::from(oprfKeyId),
                    epoch: ShareEpoch::from(epoch),
                }
            }
            Some(&OprfKeyRegistry::SecretGenRound3::SIGNATURE_HASH) => {
                let OprfKeyRegistry::SecretGenRound3 { oprfKeyId } = decode!();
                Self::Round3 {
                    key_id: OprfKeyId::from(oprfKeyId),
                    epoch: ShareEpoch::default(),
                    contributions: Contributions::Full,
                }
            }
            Some(&OprfKeyRegistry::SecretGenFinalize::SIGNATURE_HASH) => {
                let OprfKeyRegistry::SecretGenFinalize { oprfKeyId, epoch } = decode!();
                Self::Finalize {
                    key_id: OprfKeyId::from(oprfKeyId),
                    epoch: ShareEpoch::from(epoch),
                }
            }
            Some(&OprfKeyRegistry::ReshareRound1::SIGNATURE_HASH) => {
                let OprfKeyRegistry::ReshareRound1 {
                    oprfKeyId, epoch, ..
                } = decode!();
                Self::ReshareRound1 {
                    key_id: OprfKeyId::from(oprfKeyId),
                    epoch: ShareEpoch::from(epoch),
                }
            }
            Some(&OprfKeyRegistry::ReshareRound3::SIGNATURE_HASH) => {
                let OprfKeyRegistry::ReshareRound3 {
                    oprfKeyId,
                    lagrange,
                    epoch,
                } = decode!();
                tracing::trace!("parsing lagrange contributions..");
                let lagrange = lagrange
                    .into_iter()
                    .filter_map(|x| {
                        if x.is_zero() {
                            // filter the empty coefficients - the smart contract produces lagrange coeffs 0 for the not relevant parties
                            None
                        } else {
                            Some(oprf_types::chain::try_u256_into_bjj_fr(x))
                        }
                    })
                    .collect::<eyre::Result<Vec<_>>>()
                    .context("while parsing lagrange coeffs from chain")?;
                Self::Round3 {
                    key_id: OprfKeyId::from(oprfKeyId),
                    epoch: ShareEpoch::from(epoch),
                    contributions: Contributions::Shamir(lagrange),
                }
            }
            Some(&OprfKeyRegistry::KeyGenAbort::SIGNATURE_HASH) => {
                let OprfKeyRegistry::KeyGenAbort { oprfKeyId } = decode!();
                Self::Abort {
                    key_id: OprfKeyId::from(oprfKeyId),
                }
            }
            Some(&OprfKeyRegistry::KeyDeletion::SIGNATURE_HASH) => {
                let OprfKeyRegistry::KeyDeletion { oprfKeyId } = decode!();
                Self::Delete {
                    key_id: OprfKeyId::from(oprfKeyId),
                }
            }
            Some(&OprfKeyRegistry::NotEnoughProducers::SIGNATURE_HASH) => {
                let OprfKeyRegistry::NotEnoughProducers { oprfKeyId } = decode!();
                Self::NotEnoughProducers {
                    key_id: OprfKeyId::from(oprfKeyId),
                }
            }
            x => {
                tracing::warn!("unknown event: {x:?}");
                Self::Unknown
            }
        };
        Ok(event)
    }
}

impl KeyRegistryEvent {
    /// Populate the current tracing span with event-specific fields.
    ///
    /// Fields recorded (subject to variant):
    /// * `oprf_key_id` — always recorded.
    /// * `share_epoch` — recorded for variants that carry an epoch (`Round2`, `Round3`,
    ///   `Finalize`, `ReshareRound1`).
    /// * `event` — always recorded; the value is a static string name for the event type
    ///   (e.g. `"keygen-round1"`, `"round2"`, …).
    pub(super) fn record_span_fields(&self, span: &tracing::Span) {
        match self {
            KeyRegistryEvent::KeyGenRound1 { key_id }
            | KeyRegistryEvent::Delete { key_id }
            | KeyRegistryEvent::Abort { key_id }
            | KeyRegistryEvent::NotEnoughProducers { key_id } => {
                record_oprf_key_id(*key_id, span);
            }
            KeyRegistryEvent::Round2 { key_id, epoch }
            | KeyRegistryEvent::Finalize { key_id, epoch }
            | KeyRegistryEvent::ReshareRound1 { key_id, epoch }
            | KeyRegistryEvent::Round3 { key_id, epoch, .. } => {
                record_oprf_key_id(*key_id, span);
                record_share_epoch(*epoch, span);
            }
            KeyRegistryEvent::Unknown => {}
        }
        span.record("event", self.event_type());
    }

    fn event_type(&self) -> &'static str {
        match self {
            Self::KeyGenRound1 { .. } => "keygen-round1",
            Self::Round2 { .. } => "round2",
            Self::Round3 { .. } => "round3",
            Self::Finalize { .. } => "finalize",
            Self::ReshareRound1 { .. } => "reshare-round1",
            Self::Delete { .. } => "delete",
            Self::Abort { .. } => "abort",
            Self::NotEnoughProducers { .. } => "not-enough-producers",
            Self::Unknown => "unknown",
        }
    }
}

#[inline]
fn record_oprf_key_id(oprf_key_id: OprfKeyId, span: &tracing::Span) {
    span.record("oprf_key_id", oprf_key_id.to_string());
}

#[inline]
fn record_share_epoch(epoch: ShareEpoch, span: &tracing::Span) {
    span.record("share_epoch", epoch.to_string());
}
