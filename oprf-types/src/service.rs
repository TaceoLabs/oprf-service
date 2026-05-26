//! Types for communication between key-gen and nodes.
use alloy::primitives::Address;
use sqlx::{Row, postgres::PgRow};

use crate::crypto::PartyId;

/// All information necessary for an OPRF node provided by the key-gen instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInformation {
    party_id: PartyId,
    address: Address,
}

impl<'r> sqlx::FromRow<'r, PgRow> for NodeInformation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let party_id: i32 = row.try_get("party_id")?;
        let address: String = row.try_get("evm_address")?;
        let Ok(party_id) = u16::try_from(party_id) else {
            return Err(sqlx::Error::ColumnDecode {
                index: "party_id".to_owned(),
                source: "party_id does not fit into u16".into(),
            });
        };
        let Ok(address) = Address::parse_checksummed(address, None) else {
            return Err(sqlx::Error::ColumnDecode {
                index: "evm_address".to_owned(),
                source: "invalid address stored in DB".into(),
            });
        };
        Ok(Self {
            party_id: PartyId(party_id),
            address,
        })
    }
}

impl NodeInformation {
    /// Creates a new instance.
    #[must_use]
    pub fn new(party_id: PartyId, address: Address) -> Self {
        Self { party_id, address }
    }

    /// The [`PartyId`] of the node operator.
    #[must_use]
    pub fn party_id(&self) -> PartyId {
        self.party_id
    }

    /// The EVM address of the node operator.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }
}
