//! Types for communication between key-gen and nodes.
use std::num::NonZeroU16;

use sqlx::{Row, postgres::PgRow};

use crate::crypto::PartyId;

/// All information necessary for an OPRF node provided by the key-gen instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInformation {
    party_id: PartyId,
    address: String,
    threshold: NonZeroU16,
}

impl<'r> sqlx::FromRow<'r, PgRow> for NodeInformation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let party_id: i32 = row.try_get("party_id")?;
        let address: String = row.try_get("eth_address")?;
        let threshold: i32 = row.try_get("threshold")?;
        let Ok(party_id) = u16::try_from(party_id) else {
            return Err(sqlx::Error::ColumnDecode {
                index: "party_id".to_owned(),
                source: "party_id does not fit into u16".into(),
            });
        };
        let Ok(threshold_u16) = u16::try_from(threshold) else {
            return Err(sqlx::Error::ColumnDecode {
                index: "threshold".to_owned(),
                source: format!("expects non-zero u16 threshold, but got {threshold}").into(),
            });
        };
        let Some(threshold) = NonZeroU16::new(threshold_u16) else {
            return Err(sqlx::Error::ColumnDecode {
                index: "threshold".to_owned(),
                source: format!("expects non-zero threshold, but got {threshold}").into(),
            });
        };
        Ok(Self {
            party_id: PartyId(party_id),
            address,
            threshold,
        })
    }
}

impl NodeInformation {
    /// Creates a new instance.
    #[must_use]
    pub fn new(party_id: PartyId, address: String, threshold: NonZeroU16) -> Self {
        Self {
            party_id,
            address,
            threshold,
        }
    }

    /// The [`PartyId`] of the node operator.
    #[must_use]
    pub fn party_id(&self) -> PartyId {
        self.party_id
    }

    /// The EVM address of the node operator as `String`.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The threshold for the OPRF MPC instance.
    #[must_use]
    pub fn threshold(&self) -> NonZeroU16 {
        self.threshold
    }
}
