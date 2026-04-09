use std::time::Duration;

#[cfg(feature = "deploy-anvil")]
pub mod deploy_anvil;
mod oprf_key_registry;
mod secret_manager;
#[cfg(feature = "deploy-anvil")]
pub mod setup;

#[cfg(feature = "deploy-anvil")]
pub use deploy_anvil::*;
#[cfg(feature = "deploy-anvil")]
pub use setup::*;

pub use oprf_key_registry::*;

#[cfg(feature = "postgres-test-container")]
pub use secret_manager::postgres::*;

#[cfg(feature = "ci")]
pub const TEST_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(not(feature = "ci"))]
pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

pub use secret_manager::test_secret_manager;
