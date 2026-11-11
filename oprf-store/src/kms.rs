//! Wrapping of data encryption keys (DEKs) with a key management service (KMS).
//!
//! A DEK is only ever persisted wrapped by a KMS key. [`DekWrapper`] is the abstraction over the
//! wrap/unwrap step: `AwsKmsWrapper` (feature `aws-kms`) talks to AWS KMS and
//! `InMemoryWrapper` (feature `test-utils`) behaves like it for tests.

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

/// Wraps and unwraps data encryption keys with a KMS key.
#[async_trait]
pub trait DekWrapper: Send + Sync {
    /// The identifier (ARN) of the KMS key that wraps the data keys.
    fn key_arn(&self) -> &str;

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
    async fn unwrap(
        &self,
        data_key_id: Uuid,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KmsError>;
}

/// The KMS encryption context binding a wrapped data key to its identifier.
///
/// Single source of the context for every [`DekWrapper`] implementation.
#[cfg(any(feature = "aws-kms", feature = "test-utils"))]
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
    fn key_arn(&self) -> &str {
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
        self.check_key_id(output.key_id.take())?;
        let plaintext = output
            .plaintext
            .take()
            .ok_or(KmsError::MalformedResponse("missing plaintext"))?;
        let key = key_from_plaintext(plaintext.into_inner())?;
        let wrapped = output
            .ciphertext_blob
            .take()
            .ok_or(KmsError::MalformedResponse("missing ciphertext blob"))?
            .into_inner();
        Ok((key, wrapped))
    }

    async fn unwrap(
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
        self.check_key_id(output.key_id.take())?;
        let plaintext = output
            .plaintext
            .take()
            .ok_or(KmsError::MalformedResponse("missing plaintext"))?;
        key_from_plaintext(plaintext.into_inner())
    }
}

/// A [`DekWrapper`] for tests that wraps data keys with AES-256-GCM under a master key.
///
/// Like KMS it binds the wrapped key to the encryption context, so unwrapping for another
/// `data_key_id` or under another master key fails.
#[cfg(feature = "test-utils")]
#[derive(Clone)]
pub struct InMemoryWrapper {
    key_arn: String,
    master: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "test-utils")]
impl std::fmt::Debug for InMemoryWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryWrapper")
            .field("key_arn", &self.key_arn)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "test-utils")]
impl InMemoryWrapper {
    /// Creates a wrapper reporting `key_arn` and wrapping under `master`.
    #[must_use]
    pub fn new(key_arn: &str, master: [u8; 32]) -> Self {
        Self {
            key_arn: key_arn.to_owned(),
            master: Zeroizing::new(master),
        }
    }

    fn master_dek(&self, data_key_id: Uuid) -> crate::Dek {
        crate::Dek::new(data_key_id, self.master.clone())
    }

    /// The AAD derived deterministically from the encryption context.
    fn aad(data_key_id: Uuid) -> Vec<u8> {
        encryption_context(data_key_id)
            .iter()
            .flat_map(|(k, v)| format!("{k}={v};").into_bytes())
            .collect()
    }
}

#[cfg(feature = "test-utils")]
#[async_trait]
impl DekWrapper for InMemoryWrapper {
    fn key_arn(&self) -> &str {
        &self.key_arn
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
            .master_dek(data_key_id)
            .seal(&Self::aad(data_key_id), key.as_slice());
        Ok((key, wrapped))
    }

    async fn unwrap(
        &self,
        data_key_id: Uuid,
        wrapped: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, KmsError> {
        let plaintext = self
            .master_dek(data_key_id)
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

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn wrapper(master: [u8; 32]) -> InMemoryWrapper {
        InMemoryWrapper::new("arn:test:key", master)
    }

    #[tokio::test]
    async fn generate_then_unwrap() {
        let w = wrapper([1; 32]);
        let id = Uuid::new_v4();
        let (plain, wrapped) = w.generate(id).await.expect("generate");
        let again = w.unwrap(id, &wrapped).await.expect("unwrap");
        assert_eq!(*plain, *again, "unwrap returns the generated plaintext");
        assert_eq!(w.key_arn(), "arn:test:key", "key arn is reported");
    }

    #[tokio::test]
    async fn unwrap_with_other_data_key_id_fails() {
        let w = wrapper([1; 32]);
        let (_, wrapped) = w.generate(Uuid::new_v4()).await.expect("generate");
        w.unwrap(Uuid::new_v4(), &wrapped)
            .await
            .expect_err("other data_key_id must fail");
    }

    #[tokio::test]
    async fn unwrap_with_other_master_fails() {
        let id = Uuid::new_v4();
        let (_, wrapped) = wrapper([1; 32]).generate(id).await.expect("generate");
        wrapper([2; 32])
            .unwrap(id, &wrapped)
            .await
            .expect_err("other master must fail");
    }

    #[test]
    fn encryption_context_is_exact() {
        let id = Uuid::parse_str("67e55044-10b1-426f-9247-bb680e5fe0c8").expect("uuid");
        assert_eq!(
            encryption_context(id),
            [
                ("purpose", "taceo-oprf-db-dek".to_owned()),
                (
                    "data_key_id",
                    "67e55044-10b1-426f-9247-bb680e5fe0c8".to_owned()
                ),
            ],
            "context must match exactly"
        );
    }
}
