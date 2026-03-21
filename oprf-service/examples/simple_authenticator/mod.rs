use async_trait::async_trait;
use oprf_types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator, OprfRequestAuthenticatorError},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ExampleOprfRequestAuth(OprfKeyId);

pub(crate) struct ExampleOprfRequestAuthenticator;

#[async_trait]
impl OprfRequestAuthenticator for ExampleOprfRequestAuthenticator {
    type RequestAuth = ExampleOprfRequestAuth;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, OprfRequestAuthenticatorError> {
        let ExampleOprfRequestAuth(oprf_key_id) = &request.auth;
        Ok(*oprf_key_id)
    }
}
