//! Per-row storage format of secret database columns.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::EnvelopeError;

/// How the secret columns of a row are stored in the database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum StorageFormat {
    /// Secrets are stored as plain serialized bytes.
    #[serde(rename = "direct")]
    Direct,
    /// Secrets are AES-256-GCM encrypted under a data key.
    #[serde(rename = "envelopeV1")]
    EnvelopeV1,
}

impl StorageFormat {
    /// The string stored in the database and used in configuration.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::EnvelopeV1 => "envelopeV1",
        }
    }
}

impl std::fmt::Display for StorageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StorageFormat {
    type Err = EnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "envelopeV1" => Ok(Self::EnvelopeV1),
            other => Err(EnvelopeError::UnknownFormat(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_round_trip() {
        for (f, s) in [
            (StorageFormat::Direct, "direct"),
            (StorageFormat::EnvelopeV1, "envelopeV1"),
        ] {
            assert_eq!(f.as_str(), s, "as_str");
            assert_eq!(s.parse::<StorageFormat>().expect("parses"), f, "from_str");
            let json = serde_json::to_string(&f).expect("serializes");
            assert_eq!(json, format!("\"{s}\""), "serde serialize");
            assert_eq!(
                serde_json::from_str::<StorageFormat>(&json).expect("deserializes"),
                f,
                "serde deserialize"
            );
        }
        for bad in ["Direct", "bogus"] {
            assert!(
                matches!(bad.parse::<StorageFormat>(), Err(EnvelopeError::UnknownFormat(s)) if s == bad),
                "{bad} must be unknown"
            );
        }
    }
}
