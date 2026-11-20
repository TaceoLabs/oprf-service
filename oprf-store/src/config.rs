//! Configuration of the storage formats a service reads, shared by the key-gen and the node.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::{
    format::StorageFormat,
    kms::{WrappingConfigError, WrappingKeyConfig},
};

/// Which storage formats secret columns are read in.
///
/// Deserialized from these fields; a combination that is not valid fails to deserialize:
///
/// | Field                     | Default    |                                                   |
/// |---------------------------|------------|---------------------------------------------------|
/// | `allowed_storage_formats` | `[direct]` | Formats accepted when reading; must not be empty. |
/// | `kms_key_arn`             | none       | Full ARN of the AWS KMS key wrapping the data keys. |
/// | `kms_endpoint`            | none       | Custom AWS KMS endpoint (e.g. for local testing). |
/// | `storage_master_key`      | none       | Master key wrapping the data keys locally, without AWS KMS: exactly 64 hex characters (32 random bytes, e.g. from `openssl rand -hex 32`). |
///
/// If `envelopeV1` is allowed, exactly one of `kms_key_arn` and `storage_master_key` is required.
/// The key-gen and the node of a party must use the same master key, and every party its own.
/// Whoever reads the master key and the database reads every secret, and without it the stored
/// secrets are lost for good: keep a backup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawStorageReadConfig")]
#[allow(
    clippy::exhaustive_enums,
    reason = "consumers must handle every way secrets are stored"
)]
pub enum StorageReadConfig {
    /// Reads `direct` only; no wrapping key is used.
    #[default]
    Direct,
    /// Reads `envelopeV1`, and `direct` too if `read_direct` is set.
    Envelope {
        /// Whether `direct` rows are read as well.
        read_direct: bool,
        /// The key wrapping the data keys.
        key: WrappingKeyConfig,
    },
}

#[derive(Deserialize)]
struct RawStorageReadConfig {
    #[serde(default = "default_allowed_storage_formats")]
    allowed_storage_formats: Vec<StorageFormat>,
    #[serde(default)]
    kms_key_arn: Option<String>,
    #[serde(default)]
    kms_endpoint: Option<String>,
    #[serde(default)]
    storage_master_key: Option<SecretString>,
}

fn default_allowed_storage_formats() -> Vec<StorageFormat> {
    vec![StorageFormat::Direct]
}

impl TryFrom<RawStorageReadConfig> for StorageReadConfig {
    type Error = StorageReadConfigError;

    fn try_from(raw: RawStorageReadConfig) -> Result<Self, Self::Error> {
        let allows = |format| raw.allowed_storage_formats.contains(&format);
        let read_direct = allows(StorageFormat::Direct);
        if !allows(StorageFormat::EnvelopeV1) {
            return if read_direct {
                Ok(Self::Direct)
            } else {
                Err(StorageReadConfigError::NoAllowedFormats)
            };
        }
        let key = WrappingKeyConfig::parse(
            raw.kms_key_arn,
            raw.kms_endpoint,
            raw.storage_master_key
                .as_ref()
                .map(ExposeSecret::expose_secret),
        )?;
        Ok(Self::Envelope { read_direct, key })
    }
}

#[derive(Debug, thiserror::Error)]
enum StorageReadConfigError {
    #[error("allowed_storage_formats must not be empty")]
    NoAllowedFormats,
    #[error(transparent)]
    WrappingKey(#[from] WrappingConfigError),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::kms::{KeyArn, KmsConfig, LocalKeyWrapper};

    const KEY_ARN: &str = "arn:aws:kms:eu-central-1:000000000000:key/test";
    const MASTER_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn parse(value: serde_json::Value) -> Result<StorageReadConfig, String> {
        serde_json::from_value(value).map_err(|err| err.to_string())
    }

    #[test]
    fn parses_every_valid_combination() {
        let envelope = |read_direct| StorageReadConfig::Envelope {
            read_direct,
            key: WrappingKeyConfig::Kms(KmsConfig {
                key_arn: KeyArn::try_from(KEY_ARN.to_owned()).expect("valid ARN"),
                endpoint: None,
            }),
        };
        assert_eq!(parse(json!({})), Ok(StorageReadConfig::Direct));
        assert_eq!(
            parse(
                json!({ "allowed_storage_formats": ["direct", "envelopeV1"], "kms_key_arn": KEY_ARN })
            ),
            Ok(envelope(true))
        );
        assert_eq!(
            parse(json!({ "allowed_storage_formats": ["envelopeV1"], "kms_key_arn": KEY_ARN })),
            Ok(envelope(false))
        );
        assert_eq!(
            parse(
                json!({ "allowed_storage_formats": ["envelopeV1"], "storage_master_key": MASTER_KEY })
            ),
            Ok(StorageReadConfig::Envelope {
                read_direct: false,
                key: WrappingKeyConfig::Local(
                    LocalKeyWrapper::from_hex(MASTER_KEY).expect("valid key")
                ),
            })
        );
    }

    #[test]
    fn rejects_invalid_combinations() {
        for (config, field) in [
            (
                json!({ "allowed_storage_formats": [] }),
                "allowed_storage_formats",
            ),
            (
                json!({ "allowed_storage_formats": ["envelopeV1"] }),
                "kms_key_arn or storage_master_key",
            ),
            (
                json!({
                    "allowed_storage_formats": ["envelopeV1"],
                    "kms_key_arn": KEY_ARN,
                    "storage_master_key": MASTER_KEY,
                }),
                "mutually exclusive",
            ),
            (
                json!({ "allowed_storage_formats": ["envelopeV1"], "storage_master_key": "abcd" }),
                "storage_master_key",
            ),
            (
                json!({
                    "allowed_storage_formats": ["envelopeV1"],
                    "kms_key_arn": "arn:aws:kms:eu-central-1:000000000000:alias/oprf",
                }),
                "full key ARN",
            ),
        ] {
            let err = parse(config).expect_err("invalid config");
            assert!(err.contains(field), "the error must name {field}: {err}");
        }
    }
}
