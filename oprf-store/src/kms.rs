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
    /// Region and credentials come from the default AWS configuration of the environment.
    /// `endpoint` overrides the KMS endpoint URL if set.
    pub async fn new(key_arn: String, endpoint: Option<String>) -> Self {
        let mut loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
        if let Some(endpoint) = endpoint {
            loader = loader.endpoint_url(endpoint);
        }
        let config = loader.load().await;
        Self {
            client: aws_sdk_kms::Client::new(&config),
            key_arn,
        }
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
        let mut output = request.send().await.map_err(|e| KmsError::Call(e.into()))?;
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
        let mut output = request.send().await.map_err(|e| KmsError::Call(e.into()))?;
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
        use aes_gcm::aead::{OsRng, rand_core::RngCore};

        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut_slice());
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
