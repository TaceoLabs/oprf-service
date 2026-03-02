use axum_extra::headers::{self, Header};
use http::HeaderValue;
use serde::{Deserialize, de};

/// A custom header that clients need to send to OPRF servers to indicate their version.
#[derive(Debug, Clone)]
pub(crate) struct ProtocolVersion(pub(crate) semver::Version);

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ProtocolVersionQuery {
    pub(crate) version: Option<ProtocolVersion>,
}

impl<'a> de::Deserialize<'a> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        deserializer.deserialize_str(ProtocolVersionHeaderVisitor)
    }
}

struct ProtocolVersionHeaderVisitor;

impl<'de> de::Visitor<'de> for ProtocolVersionHeaderVisitor {
    type Value = ProtocolVersion;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A semver version header")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let version = semver::Version::parse(v).map_err(|err| {
            tracing::trace!("could not parse header version: {err:?}");
            de::Error::custom("expected semver version")
        })?;
        Ok(ProtocolVersion(version))
    }
}

impl Header for ProtocolVersion {
    fn name() -> &'static http::HeaderName {
        &oprf_types::api::OPRF_PROTOCOL_VERSION_HEADER
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        let version_req = values
            .next()
            .ok_or_else(headers::Error::invalid)?
            .to_str()
            .map_err(|err| {
                tracing::trace!("could not convert header to string: {err:?}");

                headers::Error::invalid()
            })?;
        if values.next().is_some() {
            Err(headers::Error::invalid())
        } else {
            let version = semver::Version::parse(version_req).map_err(|err| {
                tracing::trace!("could not parse header version: {err:?}");
                headers::Error::invalid()
            })?;
            Ok(ProtocolVersion(version))
        }
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        let encoded = HeaderValue::from_bytes(self.0.to_string().as_bytes())
            .expect("Cannot encode header version");
        values.extend(std::iter::once(encoded));
    }
}
