//! Associated data binding a ciphertext to the database row it is stored in.

use std::num::NonZeroU16;

use alloy::primitives::Address;
use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfPublicKey, PartyId},
};

use crate::{EnvelopeError, codec};

/// Domain separator of the AAD.
const DOMAIN: &[u8; 16] = b"TACEO-OPRF-DB-v1";

/// Which kind of row (and column group) a ciphertext belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A share of an in-progress key generation.
    PendingShare,
    /// A finished share.
    Share,
    /// Intermediate values of an in-progress key generation.
    Intermediates,
}

impl Kind {
    /// The byte that identifies this kind in the AAD. Part of the stored-data contract.
    const fn discriminant(self) -> u8 {
        match self {
            Self::PendingShare => 0x01,
            Self::Share => 0x02,
            Self::Intermediates => 0x03,
        }
    }
}

/// The deployment-wide values bound into every AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "constructed by consumers with struct literals"
)]
pub struct AadContext {
    /// Chain id of the chain the registry lives on.
    pub chain_id: u64,
    /// Address of the OPRF key registry contract.
    pub registry: Address,
    /// Id of this party.
    pub party_id: PartyId,
    /// Threshold of the key-gen.
    pub threshold: NonZeroU16,
}

/// The row-specific values bound into the AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "constructed by consumers with struct literals"
)]
pub struct RowId<'a> {
    /// The kind of row.
    pub kind: Kind,
    /// The OPRF key id of the row.
    pub oprf_key_id: OprfKeyId,
    /// The epoch of the row.
    pub epoch: ShareEpoch,
    /// The public key of the row. Must be `Some` exactly for [`Kind::Share`].
    pub public_key: Option<&'a OprfPublicKey>,
}

impl AadContext {
    /// Builds the AAD for the given row.
    ///
    /// Layout: domain (16) || kind (1) || key id (20, BE) || epoch (4, BE) || party id (2, BE)
    /// || threshold (2, BE) || public key (64, `Share` only) || chain id (8, BE) || registry (20).
    ///
    /// # Errors
    /// Returns [`EnvelopeError::PublicKeyMismatch`] if `row.public_key` is set iff
    /// `row.kind` is not [`Kind::Share`].
    pub fn aad(&self, row: &RowId<'_>) -> Result<Vec<u8>, EnvelopeError> {
        if row.public_key.is_some() != (row.kind == Kind::Share) {
            return Err(EnvelopeError::PublicKeyMismatch);
        }
        let mut aad = Vec::with_capacity(137);
        aad.extend_from_slice(DOMAIN);
        aad.push(row.kind.discriminant());
        aad.extend_from_slice(&row.oprf_key_id.into_inner().to_be_bytes::<20>());
        aad.extend_from_slice(&row.epoch.into_inner().to_be_bytes());
        aad.extend_from_slice(&self.party_id.into_inner().to_be_bytes());
        aad.extend_from_slice(&self.threshold.get().to_be_bytes());
        if let Some(pk) = row.public_key {
            aad.extend_from_slice(&codec::to_bytes(pk));
        }
        aad.extend_from_slice(&self.chain_id.to_be_bytes());
        aad.extend_from_slice(self.registry.as_slice());
        Ok(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    use ruint::aliases::U160;

    fn pk() -> OprfPublicKey {
        OprfPublicKey::from(ark_babyjubjub::EdwardsAffine::generator())
    }

    fn ctx() -> AadContext {
        AadContext {
            chain_id: 0x0102_0304_0506_0708,
            registry: Address::from([0xAA; 20]),
            party_id: PartyId(0x0B0C),
            threshold: NonZeroU16::new(2).expect("nonzero"),
        }
    }

    fn row(kind: Kind, pk: Option<&OprfPublicKey>) -> RowId<'_> {
        RowId {
            kind,
            oprf_key_id: OprfKeyId::new(U160::from(0x1122u64)),
            epoch: ShareEpoch::new(0x0A0B_0C0D),
            public_key: pk,
        }
    }

    #[test]
    fn aad_layout_share() {
        let pk = pk();
        let aad = ctx().aad(&row(Kind::Share, Some(&pk))).expect("aad");
        let pk_bytes = crate::codec::to_bytes(&pk);
        assert_eq!(pk_bytes.len(), 64, "public key serialization is 64 bytes");
        assert_eq!(aad.len(), 137, "total length");
        assert_eq!(&aad[0..16], b"TACEO-OPRF-DB-v1", "domain");
        assert_eq!(aad[16], 0x02, "kind");
        let mut id = [0u8; 20];
        id[18] = 0x11;
        id[19] = 0x22;
        assert_eq!(&aad[17..37], &id, "key id");
        assert_eq!(&aad[37..41], &[0x0A, 0x0B, 0x0C, 0x0D], "epoch");
        assert_eq!(&aad[41..43], &[0x0B, 0x0C], "party id");
        assert_eq!(&aad[43..45], &[0x00, 0x02], "threshold");
        assert_eq!(&aad[45..109], pk_bytes.as_slice(), "public key");
        assert_eq!(&aad[109..117], &[1, 2, 3, 4, 5, 6, 7, 8], "chain id");
        assert_eq!(&aad[117..137], &[0xAA; 20], "registry");
    }

    #[test]
    fn aad_layout_without_public_key() {
        let a = ctx().aad(&row(Kind::PendingShare, None)).expect("aad");
        let b = ctx().aad(&row(Kind::Intermediates, None)).expect("aad");
        assert_eq!(a.len(), 73, "pending length");
        assert_eq!(b.len(), 73, "intermediates length");
        assert_eq!(a[16], 0x01, "pending kind");
        assert_eq!(b[16], 0x03, "intermediates kind");
        for i in (0..73).filter(|i| *i != 16) {
            assert_eq!(a[i], b[i], "byte {i} equal");
        }
    }

    #[test]
    fn aad_rejects_public_key_mismatch() {
        let pk = pk();
        assert!(
            matches!(
                ctx().aad(&row(Kind::Share, None)),
                Err(EnvelopeError::PublicKeyMismatch)
            ),
            "share without key"
        );
        assert!(
            matches!(
                ctx().aad(&row(Kind::PendingShare, Some(&pk))),
                Err(EnvelopeError::PublicKeyMismatch)
            ),
            "pending with key"
        );
    }
}
