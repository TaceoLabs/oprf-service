//! Wrapping of data encryption keys (DEKs).
//!
//! A DEK is only ever persisted wrapped. [`DekWrapper`] is the abstraction over the wrap/unwrap
//! step: `AwsKmsWrapper` (feature `aws-kms`) wraps with a key held by AWS KMS and
//! [`LocalKeyWrapper`] wraps under a locally configured master key.

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Errors of the KMS layer.
///
/// No variant carries key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KmsError {
    /// A call to the KMS failed.
    #[error("KMS call failed: {0}")]
    Call(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The KMS returned a response that is missing a field or has an unexpected shape.
    #[error("malformed KMS response: {0}")]
    MalformedResponse(&'static str),
    /// The wrapped data key could not be unwrapped.
    #[error("unwrapping the data key failed")]
    Unwrap,
    /// The configured master key is not usable. Never contains the key.
    #[error("invalid master key: {0}")]
    InvalidMasterKey(&'static str),
    /// The KMS reported a different key than the configured one, e.g. because an alias or a bare
    /// key id is configured instead of the key ARN.
    #[error(
        "KMS key {configured} is configured, but the KMS reported key {returned}; configure the full key ARN"
    )]
    KeyIdMismatch {
        /// The configured key identifier.
        configured: String,
        /// The key ARN reported by the KMS.
        returned: String,
    },
}

/// The `wrapping` of data keys wrapped by AWS KMS.
pub const WRAPPING_AWS_KMS: &str = "awsKms";

/// The `wrapping` of data keys wrapped by [`LocalKeyWrapper`].
pub const WRAPPING_LOCAL_KEY_V1: &str = "localKeyV1";

/// Whether `arn` has the shape of a full KMS key ARN (`arn:...:key/...`), as opposed to an
/// alias, an alias ARN or a bare key id.
///
/// [`DekWrapper`] implementations compare the key reported by the KMS with the configured
/// one, so only the full key ARN works; configurations are checked with this up front.
#[must_use]
pub fn is_key_arn(arn: &str) -> bool {
    arn.starts_with("arn:") && arn.contains(":key/")
}

/// A full KMS key ARN (`arn:...:key/...`); see [`is_key_arn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyArn(String);

/// The string is not a full KMS key ARN.
#[derive(Debug, thiserror::Error)]
#[error("`{0}` is not a full key ARN (`arn:...:key/...`); aliases and alias ARNs are not accepted")]
pub struct InvalidKeyArn(String);

impl TryFrom<String> for KeyArn {
    type Error = InvalidKeyArn;

    fn try_from(arn: String) -> Result<Self, Self::Error> {
        if is_key_arn(&arn) {
            Ok(Self(arn))
        } else {
            Err(InvalidKeyArn(arn))
        }
    }
}

impl From<KeyArn> for String {
    fn from(arn: KeyArn) -> Self {
        arn.0
    }
}

/// The AWS KMS key that wraps the data keys.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_structs,
    reason = "constructed by consumers with struct literals"
)]
pub struct KmsConfig {
    /// The full ARN of the key.
    pub key_arn: KeyArn,
    /// Custom AWS KMS endpoint (e.g. for local testing).
    pub endpoint: Option<String>,
}

impl std::fmt::Display for KeyArn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Errors of a [`WrappingKeyConfig`]. Every message names the offending configuration field.
///
/// No variant carries key material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WrappingConfigError {
    /// Both a KMS key and a master key are configured.
    #[error("kms_key_arn and storage_master_key are mutually exclusive")]
    BothKeys,
    /// The KMS key is not given as a full key ARN.
    #[error("kms_key_arn: {0}")]
    InvalidKeyArn(#[from] InvalidKeyArn),
    /// The master key is not usable.
    #[error("storage_master_key: {0}")]
    InvalidMasterKey(KmsError),
    /// Neither a KMS key nor a master key is configured.
    #[error(
        "kms_key_arn or storage_master_key is required when envelopeV1 is an allowed storage format"
    )]
    MissingKey,
    /// A KMS key is configured, but this build has no AWS KMS support.
    #[error("kms_key_arn is configured, but the `aws-kms` feature is not enabled")]
    AwsKmsDisabled,
}

/// The key that wraps the data keys of a deployment that reads `envelopeV1`.
///
/// Shared by the key-gen and the node, so that both accept exactly the same configurations
/// and build the same [`DekWrapper`] from them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::exhaustive_enums,
    reason = "consumers must handle every kind of wrapping key"
)]
pub enum WrappingKeyConfig {
    /// A key held by AWS KMS.
    Kms(KmsConfig),
    /// A locally configured master key.
    Local(LocalKeyWrapper),
}

impl WrappingKeyConfig {
    /// Parses the key from the ARN of the AWS KMS key (`kms_key_arn`), an endpoint overriding
    /// the default AWS KMS endpoint (`kms_endpoint`) and the local master key as hex
    /// (`storage_master_key`).
    ///
    /// # Errors
    ///
    /// Returns an error if `kms_key_arn` is not a full key ARN, the master key is not usable,
    /// or both or none of them are set.
    pub fn parse(
        kms_key_arn: Option<String>,
        kms_endpoint: Option<String>,
        master_key_hex: Option<&str>,
    ) -> Result<Self, WrappingConfigError> {
        match (kms_key_arn, master_key_hex) {
            (Some(_), Some(_)) => Err(WrappingConfigError::BothKeys),
            (Some(key_arn), None) => Ok(Self::Kms(KmsConfig {
                key_arn: KeyArn::try_from(key_arn)?,
                endpoint: kms_endpoint,
            })),
            (None, Some(hex)) => LocalKeyWrapper::from_hex(hex)
                .map(Self::Local)
                .map_err(WrappingConfigError::InvalidMasterKey),
            (None, None) => Err(WrappingConfigError::MissingKey),
        }
    }

    /// Builds the wrapper of the configured key. Only a KMS key touches AWS.
    ///
    /// # Errors
    ///
    /// Returns [`WrappingConfigError::AwsKmsDisabled`] if a KMS key is configured and the
    /// `aws-kms` feature is not enabled.
    #[cfg_attr(
        not(feature = "aws-kms"),
        allow(
            clippy::unused_async,
            clippy::unused_async_trait_impl,
            reason = "only awaits with the `aws-kms` feature; the signature must not depend on it"
        )
    )]
    pub async fn wrapper(self) -> Result<Arc<dyn DekWrapper>, WrappingConfigError> {
        match self {
            Self::Local(local) => Ok(Arc::new(local)),
            #[cfg(feature = "aws-kms")]
            Self::Kms(kms) => Ok(Arc::new(
                AwsKmsWrapper::new(kms.key_arn.into(), kms.endpoint).await,
            )),
            #[cfg(not(feature = "aws-kms"))]
            Self::Kms(_) => Err(WrappingConfigError::AwsKmsDisabled),
        }
    }
}

/// Wraps and unwraps data encryption keys with a KMS key.
#[async_trait]
pub trait DekWrapper: Send + Sync {
    /// How this wrapper wraps data keys; stored in the `wrapping` column of every data key.
    fn wrapping(&self) -> &'static str;

    /// The identifier of the key that wraps the data keys: the key ARN for AWS KMS, a
    /// fingerprint of the master key for [`LocalKeyWrapper`].
    fn key_id(&self) -> &str;

    /// Generates a fresh 32-byte data key bound to `data_key_id`.
    ///
    /// Returns `(plaintext, wrapped)`.
    ///
    /// # Errors
    ///
    /// Returns a [`KmsError`] if the KMS call fails or returns a malformed response.
    async fn generate(&self, data_key_id: Uuid)
    -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KmsError>;

    /// Unwraps a data key previously returned by [`DekWrapper::generate`] for the same `data_key_id`.
    ///
    /// # Errors
    ///
    /// Returns a [`KmsError`] if the KMS call fails, the key was wrapped for another
    /// `data_key_id` or under another KMS key, or the response is malformed.
    async fn unwrap_dek(
        &self,
        data_key_id: Uuid,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KmsError>;
}

/// The KMS encryption context binding a wrapped data key to its identifier.
///
/// Single source of the context for every [`DekWrapper`] implementation.
#[cfg(feature = "aws-kms")]
pub(crate) fn encryption_context(data_key_id: Uuid) -> [(&'static str, String); 2] {
    [
        ("purpose", "taceo-oprf-db-dek".to_owned()),
        ("data_key_id", data_key_id.hyphenated().to_string()),
    ]
}

/// Copies a KMS plaintext into a fixed-size zeroizing key, zeroizing the source buffer.
#[cfg(feature = "aws-kms")]
fn key_from_plaintext(plaintext: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, KmsError> {
    let plaintext = Zeroizing::new(plaintext);
    let mut key = Zeroizing::new([0u8; 32]);
    if plaintext.len() != key.len() {
        return Err(KmsError::MalformedResponse("data key is not 32 bytes"));
    }
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Timeout of a whole KMS operation, including retries.
#[cfg(feature = "aws-kms")]
const OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Timeout of a single attempt of a KMS operation.
#[cfg(feature = "aws-kms")]
const OPERATION_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Wraps an AWS SDK error into [`KmsError::Call`], keeping its full error chain in the message.
#[cfg(feature = "aws-kms")]
fn call_error<E: std::error::Error>(error: E) -> KmsError {
    KmsError::Call(
        aws_sdk_kms::error::DisplayErrorContext(error)
            .to_string()
            .into(),
    )
}

/// A [`DekWrapper`] backed by AWS KMS.
#[cfg(feature = "aws-kms")]
#[derive(Debug, Clone)]
pub struct AwsKmsWrapper {
    client: aws_sdk_kms::Client,
    key_arn: String,
}

#[cfg(feature = "aws-kms")]
impl AwsKmsWrapper {
    /// Creates a wrapper for the KMS key `key_arn`.
    ///
    /// `key_arn` must be the full key ARN, not an alias or a bare key id: every KMS response is
    /// checked against it and a mismatch fails with [`KmsError::KeyIdMismatch`].
    ///
    /// Region and credentials come from the default AWS configuration of the environment.
    /// `endpoint` overrides the KMS endpoint URL if set.
    ///
    /// Every KMS operation times out after 30 s and each attempt after 10 s, so an endpoint that
    /// accepts the connection but never answers fails instead of hanging.
    pub async fn new(key_arn: String, endpoint: Option<String>) -> Self {
        let timeouts = aws_sdk_kms::config::timeout::TimeoutConfig::builder()
            .operation_timeout(OPERATION_TIMEOUT)
            .operation_attempt_timeout(OPERATION_ATTEMPT_TIMEOUT)
            .build();
        let mut loader =
            aws_config::defaults(aws_config::BehaviorVersion::latest()).timeout_config(timeouts);
        if let Some(endpoint) = endpoint {
            loader = loader.endpoint_url(endpoint);
        }
        let config = loader.load().await;
        Self {
            client: aws_sdk_kms::Client::new(&config),
            key_arn,
        }
    }

    /// Checks that the key reported by the KMS is exactly the configured key ARN.
    fn check_key_id(&self, returned: Option<String>) -> Result<(), KmsError> {
        let returned = returned.ok_or(KmsError::MalformedResponse("missing key id"))?;
        if returned != self.key_arn {
            return Err(KmsError::KeyIdMismatch {
                configured: self.key_arn.clone(),
                returned,
            });
        }
        Ok(())
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl DekWrapper for AwsKmsWrapper {
    fn wrapping(&self) -> &'static str {
        WRAPPING_AWS_KMS
    }

    fn key_id(&self) -> &str {
        &self.key_arn
    }

    async fn generate(
        &self,
        data_key_id: Uuid,
    ) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KmsError> {
        let mut request = self
            .client
            .generate_data_key()
            .key_id(&self.key_arn)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256);
        for (k, v) in encryption_context(data_key_id) {
            request = request.encryption_context(k, v);
        }
        let mut output = request.send().await.map_err(call_error)?;
        let plaintext = output
            .plaintext
            .take()
            .ok_or(KmsError::MalformedResponse("missing plaintext"))?;
        // Owned by a zeroizing key before any check can return early.
        let key = key_from_plaintext(plaintext.into_inner())?;
        self.check_key_id(output.key_id.take())?;
        let wrapped = output
            .ciphertext_blob
            .take()
            .ok_or(KmsError::MalformedResponse("missing ciphertext blob"))?
            .into_inner();
        Ok((key, wrapped))
    }

    async fn unwrap_dek(
        &self,
        data_key_id: Uuid,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KmsError> {
        let mut request = self
            .client
            .decrypt()
            .key_id(&self.key_arn)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(wrapped));
        for (k, v) in encryption_context(data_key_id) {
            request = request.encryption_context(k, v);
        }
        let mut output = request.send().await.map_err(call_error)?;
        let plaintext = output
            .plaintext
            .take()
            .ok_or(KmsError::MalformedResponse("missing plaintext"))?;
        // Owned by a zeroizing key before any check can return early.
        let key = key_from_plaintext(plaintext.into_inner())?;
        self.check_key_id(output.key_id.take())?;
        Ok(key)
    }
}

/// Lowercase hex encoding of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// The info string HKDF expands the master key with to get the key that wraps data keys.
const LOCAL_WRAP_KEY_INFO: &[u8] = b"taceo-oprf-db-master-key/v1/wrap";

/// The info string HKDF expands the master key with to get the public key identifier.
const LOCAL_KEY_ID_INFO: &[u8] = b"taceo-oprf-db-master-key/v1/id";

/// The domain separator of the AAD a wrapped data key is bound to.
const LOCAL_WRAP_AAD_DOMAIN: &[u8] = b"taceo-oprf-db-dek-wrap-v1";

/// A [`DekWrapper`] that wraps data keys under a locally configured 32-byte master key, without
/// any KMS.
///
/// Two independent values are derived from the master key with HKDF-SHA256: the key that wraps
/// the data keys, and a public identifier of the master key (`local:<32 hex characters>`) that
/// is stored with every data key. A process configured with another master key therefore fails
/// with a key mismatch instead of an opaque unwrap failure.
///
/// A wrapped data key is `nonce (12 bytes) || ciphertext (32 bytes) || tag (16 bytes)` of
/// AES-256-GCM under the wrapping key, bound to the `data_key_id` through the AAD.
///
/// Compared to a KMS, the master key lives in the configuration of the process: whoever reads
/// it together with the database reads every secret, and losing it loses every secret. Each
/// party must use its own master key.
#[derive(Clone)]
pub struct LocalKeyWrapper {
    key_id: String,
    wrap_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for LocalKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeyWrapper")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Two wrappers are equal if they have the same master key; compared by the public identifier.
impl PartialEq for LocalKeyWrapper {
    fn eq(&self, other: &Self) -> bool {
        self.key_id == other.key_id
    }
}

impl Eq for LocalKeyWrapper {}

impl LocalKeyWrapper {
    /// Creates a wrapper for the master key `master`.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError::InvalidMasterKey`] if all bytes of `master` are equal: such a key is
    /// a placeholder, not a random key.
    ///
    /// # Panics
    ///
    /// Never; the derived lengths are valid HKDF-SHA256 output lengths.
    pub fn new(master: &[u8; 32]) -> Result<Self, KmsError> {
        if master.iter().all(|b| *b == master[0]) {
            return Err(KmsError::InvalidMasterKey(
                "all bytes are equal; generate a random key, e.g. with `openssl rand -hex 32`",
            ));
        }
        let hkdf = hkdf::Hkdf::<sha2::Sha256>::new(None, master);
        let mut wrap_key = Zeroizing::new([0u8; 32]);
        hkdf.expand(LOCAL_WRAP_KEY_INFO, wrap_key.as_mut_slice())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        let mut id = [0u8; 16];
        hkdf.expand(LOCAL_KEY_ID_INFO, &mut id)
            .expect("16 bytes is a valid HKDF-SHA256 output length");
        Ok(Self {
            key_id: format!("local:{}", to_hex(&id)),
            wrap_key,
        })
    }

    /// Creates a wrapper for a master key given as exactly 64 hex characters.
    ///
    /// Surrounding whitespace is ignored, so that a key read from a file with a trailing
    /// newline (e.g. written by `openssl rand -hex 32 > file`) is accepted.
    ///
    /// # Errors
    ///
    /// Returns [`KmsError::InvalidMasterKey`] if `hex` is not exactly 64 hex characters after
    /// trimming or the key is rejected by [`LocalKeyWrapper::new`]. The error never contains
    /// the input.
    ///
    /// # Panics
    ///
    /// Never, like [`LocalKeyWrapper::new`].
    pub fn from_hex(hex: &str) -> Result<Self, KmsError> {
        const fn nibble(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        }
        let hex = hex.trim().as_bytes();
        let mut master = Zeroizing::new([0u8; 32]);
        if hex.len() != 2 * master.len() {
            return Err(KmsError::InvalidMasterKey(
                "expected exactly 64 hex characters (32 bytes)",
            ));
        }
        for (byte, pair) in master.iter_mut().zip(hex.as_chunks::<2>().0) {
            let (Some(high), Some(low)) = (nibble(pair[0]), nibble(pair[1])) else {
                return Err(KmsError::InvalidMasterKey(
                    "expected exactly 64 hex characters (32 bytes)",
                ));
            };
            *byte = (high << 4) | low;
        }
        Self::new(&master)
    }

    fn wrap_dek(&self, data_key_id: Uuid) -> crate::Dek {
        crate::Dek::new(data_key_id, &self.wrap_key)
    }

    /// The AAD binding a wrapped data key to its identifier.
    fn aad(data_key_id: Uuid) -> Vec<u8> {
        let mut aad = Vec::with_capacity(LOCAL_WRAP_AAD_DOMAIN.len() + 16);
        aad.extend_from_slice(LOCAL_WRAP_AAD_DOMAIN);
        aad.extend_from_slice(data_key_id.as_bytes());
        aad
    }
}

#[async_trait]
impl DekWrapper for LocalKeyWrapper {
    fn wrapping(&self) -> &'static str {
        WRAPPING_LOCAL_KEY_V1
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn generate(
        &self,
        data_key_id: Uuid,
    ) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>), KmsError> {
        let mut key = Zeroizing::new([0u8; 32]);
        // Filled in place from the operating system RNG.
        aes_gcm::aead::common::getrandom::fill(key.as_mut_slice())
            .expect("the operating system RNG must not fail");
        let wrapped = self
            .wrap_dek(data_key_id)
            .seal(&Self::aad(data_key_id), key.as_slice());
        Ok((key, wrapped))
    }

    async fn unwrap_dek(
        &self,
        data_key_id: Uuid,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KmsError> {
        let plaintext = self
            .wrap_dek(data_key_id)
            .open(&Self::aad(data_key_id), wrapped)
            .map_err(|_| KmsError::Unwrap)?;
        let mut key = Zeroizing::new([0u8; 32]);
        if plaintext.len() != key.len() {
            return Err(KmsError::Unwrap);
        }
        key.copy_from_slice(&plaintext);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const DATA_KEY_ID: &str = "67e55044-10b1-426f-9247-bb680e5fe0c8";

    fn master() -> [u8; 32] {
        std::array::from_fn(|i| u8::try_from(i).expect("fits"))
    }

    fn other_master() -> [u8; 32] {
        std::array::from_fn(|i| u8::try_from(i + 1).expect("fits"))
    }

    fn data_key_id() -> Uuid {
        Uuid::parse_str(DATA_KEY_ID).expect("uuid")
    }

    #[cfg(feature = "aws-kms")]
    #[test]
    fn encryption_context_is_exact() {
        assert_eq!(
            encryption_context(data_key_id()),
            [
                ("purpose", "taceo-oprf-db-dek".to_owned()),
                ("data_key_id", DATA_KEY_ID.to_owned()),
            ],
            "context must match exactly"
        );
    }

    #[tokio::test]
    async fn local_key_round_trip() {
        let wrapper = LocalKeyWrapper::new(&master()).expect("valid key");
        let (key, blob) = wrapper.generate(data_key_id()).await.expect("generate");
        assert_eq!(blob.len(), 12 + 32 + 16, "nonce + key + tag");
        let unwrapped = wrapper
            .unwrap_dek(data_key_id(), &blob)
            .await
            .expect("unwrap");
        assert_eq!(
            *unwrapped, *key,
            "unwrapped key must equal the generated key"
        );
        let (other_key, _) = wrapper.generate(data_key_id()).await.expect("generate");
        assert_ne!(*other_key, *key, "every generated key is fresh");
    }

    #[tokio::test]
    async fn local_key_unwrap_rejects() {
        let wrapper = LocalKeyWrapper::new(&master()).expect("valid key");
        let (_, blob) = wrapper.generate(data_key_id()).await.expect("generate");

        let other_id = Uuid::from_u128(1);
        let other = LocalKeyWrapper::new(&other_master()).expect("valid key");
        let mut modified = blob.clone();
        *modified.last_mut().expect("not empty") ^= 1;
        for (name, result) in [
            (
                "another data key id",
                wrapper.unwrap_dek(other_id, &blob).await,
            ),
            (
                "another master key",
                other.unwrap_dek(data_key_id(), &blob).await,
            ),
            (
                "modified bytes",
                wrapper.unwrap_dek(data_key_id(), &modified).await,
            ),
            (
                "truncated bytes",
                wrapper.unwrap_dek(data_key_id(), &blob[..20]).await,
            ),
            ("empty bytes", wrapper.unwrap_dek(data_key_id(), &[]).await),
        ] {
            assert!(matches!(result, Err(KmsError::Unwrap)), "{name}");
        }
    }

    /// Pins the stored format: key derivation, key id, AAD and layout of a blob key.
    ///
    /// The key id was also checked against an independent HKDF-SHA256 implementation. If this
    /// test fails, existing `localKeyV1` data keys became unreadable.
    #[tokio::test]
    async fn local_key_known_answer() {
        fn unhex(hex: &str) -> Vec<u8> {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect()
        }
        let wrapper = LocalKeyWrapper::new(&master()).expect("valid key");
        assert_eq!(wrapper.key_id(), "local:4afff713b8523626c3c923a845f88571");
        let blob = unhex(
            "e540e7b9b1941c9ae048c107d8ba13bad1f0e2c84d5a1c9fb5c012798e24e2d8\
             00c2321d8b02bda36746d7759c9595fb016079ffee99bed612725019",
        );
        let key = wrapper
            .unwrap_dek(data_key_id(), &blob)
            .await
            .expect("unwrap");
        assert_eq!(
            key.as_slice(),
            unhex("64ee304b284710c6c231743a73439f0c7be3dc341c53a019d0524ba8d2e908fc"),
        );
    }

    #[test]
    fn local_key_id_depends_on_master_key_only() {
        let a = LocalKeyWrapper::new(&master()).expect("valid key");
        let b = LocalKeyWrapper::new(&master()).expect("valid key");
        let other = LocalKeyWrapper::new(&other_master()).expect("valid key");
        assert_eq!(a.key_id(), b.key_id(), "same master key, same id");
        assert_ne!(a.key_id(), other.key_id(), "other master key, other id");
        assert_eq!(a.wrapping(), "localKeyV1");
    }

    #[test]
    fn local_key_from_hex() {
        let from_hex = LocalKeyWrapper::from_hex(MASTER_HEX).expect("valid hex");
        let upper = LocalKeyWrapper::from_hex(&MASTER_HEX.to_uppercase()).expect("valid hex");
        let from_bytes = LocalKeyWrapper::new(&master()).expect("valid key");
        assert_eq!(from_hex.key_id(), from_bytes.key_id());
        assert_eq!(upper.key_id(), from_bytes.key_id());
        for padded in [
            format!("{MASTER_HEX}\n"),
            format!("{MASTER_HEX}\r\n"),
            format!("  {MASTER_HEX}\t"),
        ] {
            let trimmed = LocalKeyWrapper::from_hex(&padded).expect("whitespace is trimmed");
            assert_eq!(trimmed.key_id(), from_bytes.key_id());
        }
        let inner_space = format!("{} {}", &MASTER_HEX[..32], &MASTER_HEX[32..]);
        LocalKeyWrapper::from_hex(&inner_space).expect_err("inner whitespace is rejected");

        let prefixed = format!("0x{MASTER_HEX}");
        let not_hex = format!("{}zz", &MASTER_HEX[..62]);
        let weak = "ab".repeat(32);
        for bad in ["", &MASTER_HEX[..62], &prefixed, &not_hex, &weak] {
            let err = LocalKeyWrapper::from_hex(bad).expect_err("must be rejected");
            assert!(matches!(err, KmsError::InvalidMasterKey(_)), "{bad}");
            if !bad.is_empty() {
                assert!(
                    !err.to_string().contains(bad),
                    "error must not echo the key"
                );
            }
        }
    }

    #[test]
    fn local_key_debug_hides_key() {
        let wrapper = LocalKeyWrapper::from_hex(MASTER_HEX).expect("valid hex");
        let debug = format!("{wrapper:?}");
        assert!(debug.contains(wrapper.key_id()), "{debug}");
        assert!(!debug.contains("wrap_key"), "{debug}");
    }
}
