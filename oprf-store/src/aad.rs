//! Associated data binding a ciphertext to the database row it is stored in.

use std::num::NonZeroU16;

use oprf_types::{
    OprfKeyId, ShareEpoch,
    crypto::{OprfPublicKey, PartyId},
};

use crate::codec;

/// Domain separator of the AAD.
const DOMAIN: &[u8; 16] = b"TACEO-OPRF-DB-v1";

/// Which kind of row (and column group) a ciphertext belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// A share of an in-progress key generation.
    PendingShare,
    /// A finished share, with the public key of its OPRF key.
    Share(OprfPublicKey),
    /// Intermediate values of an in-progress key generation.
    Intermediates,
}

impl Kind {
    /// The byte that identifies this kind in the AAD. Part of the stored-data contract.
    const fn discriminant(self) -> u8 {
        match self {
            Self::PendingShare => 0x01,
            Self::Share(_) => 0x02,
            Self::Intermediates => 0x03,
        }
    }
}

/// The deployment-wide values bound into every AAD.
///
/// Nothing here identifies the deployment itself: deployments must not share a KMS key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "constructed by consumers with struct literals"
)]
pub struct AadContext {
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
pub struct RowId {
    /// The kind of row.
    pub kind: Kind,
    /// The OPRF key id of the row.
    pub oprf_key_id: OprfKeyId,
    /// The epoch of the row.
    pub epoch: ShareEpoch,
}

impl AadContext {
    /// Builds the AAD for the given row.
    ///
    /// Layout: domain (16) || kind (1) || key id (20, BE) || epoch (4, BE) || party id (2, BE)
    /// || threshold (2, BE) || public key (64, `Share` only).
    #[must_use]
    pub fn aad(&self, row: &RowId) -> Vec<u8> {
        let mut aad = Vec::with_capacity(109);
        aad.extend_from_slice(DOMAIN);
        aad.push(row.kind.discriminant());
        aad.extend_from_slice(&row.oprf_key_id.into_inner().to_be_bytes::<20>());
        aad.extend_from_slice(&row.epoch.into_inner().to_be_bytes());
        aad.extend_from_slice(&self.party_id.into_inner().to_be_bytes());
        aad.extend_from_slice(&self.threshold.get().to_be_bytes());
        if let Kind::Share(pk) = &row.kind {
            aad.extend_from_slice(&codec::to_bytes(pk));
        }
        aad
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
            party_id: PartyId(0x0B0C),
            threshold: NonZeroU16::new(2).expect("nonzero"),
        }
    }

    fn row(kind: Kind) -> RowId {
        RowId {
            kind,
            oprf_key_id: OprfKeyId::new(U160::from(0x1122u64)),
            epoch: ShareEpoch::new(0x0A0B_0C0D),
        }
    }

    #[test]
    fn aad_layout_share() {
        let pk = pk();
        let aad = ctx().aad(&row(Kind::Share(pk)));
        let pk_bytes = crate::codec::to_bytes(&pk);
        assert_eq!(pk_bytes.len(), 64, "public key serialization is 64 bytes");
        assert_eq!(aad.len(), 109, "total length");
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
    }

    #[test]
    fn aad_layout_without_public_key() {
        let a = ctx().aad(&row(Kind::PendingShare));
        let b = ctx().aad(&row(Kind::Intermediates));
        assert_eq!(a.len(), 45, "pending length");
        assert_eq!(b.len(), 45, "intermediates length");
        assert_eq!(a[16], 0x01, "pending kind");
        assert_eq!(b[16], 0x03, "intermediates kind");
        for i in (0..45).filter(|i| *i != 16) {
            assert_eq!(a[i], b[i], "byte {i} equal");
        }
    }
}
