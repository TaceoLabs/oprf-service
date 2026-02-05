use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use oprf_types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ExampleOprfRequestAuth(OprfKeyId);

/// Errors returned by the [`ExampleOprfRequestAuthError`].
#[derive(Debug, thiserror::Error)]
#[allow(unused)]
pub(crate) enum ExampleOprfRequestAuthError {
    #[error("invalid")]
    Invalid,
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for ExampleOprfRequestAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ExampleOprfRequestAuthError::Invalid => {
                (StatusCode::BAD_REQUEST, "invalid").into_response()
            }
            ExampleOprfRequestAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

pub(crate) struct ExampleOprfRequestAuthenticator;

#[async_trait]
impl OprfRequestAuthenticator for ExampleOprfRequestAuthenticator {
    type RequestAuth = ExampleOprfRequestAuth;
    type RequestAuthError = ExampleOprfRequestAuthError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        let ExampleOprfRequestAuth(oprf_key_id) = &request.auth;
        Ok(*oprf_key_id)
    }
}
