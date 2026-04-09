# Changelog

## [Unreleased]

## [0.10.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.9.0...taceo-oprf-test-utils-v0.10.0)

### 🚜 Refactor


- *(dev-client)* [**breaking**] Remove test-utils dep - ([bb5f8bf](https://github.com/TaceoLabs/oprf-service/commit/bb5f8bfe9f09cafd89158304bb08c67a212c8975))
- Refactor!(test-utils): remvoe test-secert-manager macros - ([590b83a](https://github.com/TaceoLabs/oprf-service/commit/590b83a33dbe5d1aa7f8a994fc3eb9cac0326c14))


## [0.9.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.8.1...taceo-oprf-test-utils-v0.9.0)

### 🚜 Refactor


- [**breaking**] Remove AWS secretmanager backend and `aws-*` crates - ([011bf1f](https://github.com/TaceoLabs/oprf-service/commit/011bf1fc6bbfab086d5028020e63859a9105dfba))

### 🧪 Testing


- Added wallet_private_key_hex_string on test-secret-manager ([#539](https://github.com/TaceoLabs/oprf-service/pull/539)) - ([0e0fb6a](https://github.com/TaceoLabs/oprf-service/commit/0e0fb6a4af52a62b8a584030af7e95cd422a160e))

### ⚙️ Miscellaneous Tasks


- Cleanup Cargo.toml, Readme, update setup script and cargo deny - ([e7f47cb](https://github.com/TaceoLabs/oprf-service/commit/e7f47cb17d3e2171e119d3fe0913a75890e344e8))


## [0.8.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.8.0...taceo-oprf-test-utils-v0.8.1)

### ⚙️ Miscellaneous Tasks


- Update Cargo.lock dependencies - ([0000000](https://github.com/TaceoLabs/oprf-service/commit/0000000))


## [0.8.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.7.1...taceo-oprf-test-utils-v0.8.0)

### 🚜 Refactor


- *(node)* [**breaking**] Removed error type from secret-manager for retry - ([f361b04](https://github.com/TaceoLabs/oprf-service/commit/f361b045543b195468849a483ccda3d5a8c42c88))
- *(test-utils)* [**breaking**] Refactor service_test_secret_manager macro - ([6bd6e27](https://github.com/TaceoLabs/oprf-service/commit/6bd6e2735191746061a199759f50f0f1e166c479))
- [**breaking**] Move from clap to config [TAC-475] ([#506](https://github.com/TaceoLabs/oprf-service/pull/506)) - ([d33a65b](https://github.com/TaceoLabs/oprf-service/commit/d33a65bdce4d3dcc7c2f4067be52313b8f470447))


## [0.7.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.7.0...taceo-oprf-test-utils-v0.7.1)

### 📚 Documentation


- Update Readme to reflect state of repository. ([#494](https://github.com/TaceoLabs/oprf-service/pull/494)) - ([4cb63b0](https://github.com/TaceoLabs/oprf-service/commit/4cb63b02f4615bdb1c3a7cf90d61828b5daf439e))


## [0.7.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.6.1...taceo-oprf-test-utils-v0.7.0)

### ⚙️ Miscellaneous Tasks


- Update to zkeys from trusted setup ceremony ([#480](https://github.com/TaceoLabs/oprf-service/pull/480)) - ([c63bf1c](https://github.com/TaceoLabs/oprf-service/commit/c63bf1c1e3afe6ea8770073e4a72966549fee483))


## [0.6.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.6.0...taceo-oprf-test-utils-v0.6.1)

### ⚙️ Miscellaneous Tasks


- Update Cargo.lock dependencies - ([0000000](https://github.com/TaceoLabs/oprf-service/commit/0000000))


## [0.6.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.5.0...taceo-oprf-test-utils-v0.6.0)

### 🐛 Bug Fixes


- Correct some combination of features not building ([#465](https://github.com/TaceoLabs/oprf-service/pull/465)) - ([5ff3b85](https://github.com/TaceoLabs/oprf-service/commit/5ff3b8549bd2b526bedc069549538a348d7b47b2))


## [0.5.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.4.0...taceo-oprf-test-utils-v0.5.0)

### 🐛 Bug Fixes


- [**breaking**] Dont rely on caller of secret_manager impl macros to have its external deps, use different mod names for both ([#461](https://github.com/TaceoLabs/oprf-service/pull/461)) - ([d9c3241](https://github.com/TaceoLabs/oprf-service/commit/d9c3241d80c61dafcd555aaa294d260518ea2a2e))

### 🧪 Testing


- Add exhaustive tests for node ([#456](https://github.com/TaceoLabs/oprf-service/pull/456)) - ([cb42ef9](https://github.com/TaceoLabs/oprf-service/commit/cb42ef99722da5a56944ced275fde42ae508776e))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.3.0...taceo-oprf-test-utils-v0.4.0)

### 🐛 Bug Fixes


- Handle revert reasons during key-gen more gracefully ([#451](https://github.com/TaceoLabs/oprf-service/pull/451)) - ([d16321c](https://github.com/TaceoLabs/oprf-service/commit/d16321c98fde0aa1ed30aa380f0700baf6e91c1c))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.2.1...taceo-oprf-test-utils-v0.3.0)

### ⛰️ Features


- [**breaking**] Ping secret-manager to wake up from deep-sleep when doing key-gen ([#447](https://github.com/TaceoLabs/oprf-service/pull/447)) - ([e01827b](https://github.com/TaceoLabs/oprf-service/commit/e01827bbd5c6f1ccdb24389f6fedec81135eb479))
- [**breaking**] Add task that periodically refreshes shares for nodes - ([68a0344](https://github.com/TaceoLabs/oprf-service/commit/68a034422c75bfab4b21641a4e3acc76803e8cd9))

### 🚜 Refactor


- [**breaking**] Cleanup (remarks DK) - ([ec2a3de](https://github.com/TaceoLabs/oprf-service/commit/ec2a3defa6bc5e01bafd595628d2add281885e35))
- [**breaking**] Uses constant backoff for DB queries in service/key-gen - ([cf919d0](https://github.com/TaceoLabs/oprf-service/commit/cf919d0e49222c363b5cb9a18b2c45fd3358a415))

### ⚙️ Miscellaneous Tasks


- Removed unused deps - ([a33e71f](https://github.com/TaceoLabs/oprf-service/commit/a33e71f2e83523fe93410eb5ddb5dafdd524ada7))


## [0.2.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.2.0...taceo-oprf-test-utils-v0.2.1)

### 🐛 Bug Fixes


- Prevents empty schema name for postgres secret-manager ([#423](https://github.com/TaceoLabs/oprf-service/pull/423)) - ([b71d25a](https://github.com/TaceoLabs/oprf-service/commit/b71d25a88f58728f0548d12bd27e04d9c4c2528d))

### 🧪 Testing


- Added macro for key-gen/node-secret-manager in test_utils - ([91af688](https://github.com/TaceoLabs/oprf-service/commit/91af688626d3cc11b2160fd865ac155c78d7fe1c))


## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-test-utils-v0.1.0...taceo-oprf-test-utils-v0.2.0)

### 🚜 Refactor


- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))
- [**breaking**] Load address from secret-manager over config - ([7838777](https://github.com/TaceoLabs/oprf-service/commit/78387771c268c5f18b7331f825cb2fc1a16438fc))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### 🧪 Testing


- Fixes the test for schema integrations - ([6c43f15](https://github.com/TaceoLabs/oprf-service/commit/6c43f151c0278d7bb5712eec3f1511d94191f113))
- Add tests for postgres secret-manager in service - ([15c47f5](https://github.com/TaceoLabs/oprf-service/commit/15c47f591a5fefc05a9b72becb90d4140d1587f4))
- Restructure for the and moved testcontainer to test-utils - ([e5fb5b9](https://github.com/TaceoLabs/oprf-service/commit/e5fb5b901bb1b832878a47f010ab0abfa3486496))

### ⚙️ Miscellaneous Tasks


- *(test)* Renamed eth_private_key/eth_address to TEST_* to highlight that those are test keys - ([b3b95bf](https://github.com/TaceoLabs/oprf-service/commit/b3b95bfbc3bec66181ee0ea251f99364c41c52a6))


## [0.1.0]

### ⛰️ Features


- Move TestSecretManager trait impls to oprf-test-utils again ([#407](https://github.com/TaceoLabs/oprf-service/pull/407)) - ([76ad208](https://github.com/TaceoLabs/oprf-service/commit/76ad208206bd6594b4361e956e2835740595334c))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- [**breaking**] Split into oprf-key-gen and oprf-service ([#291](https://github.com/TaceoLabs/oprf-service/pull/291)) - ([294b8bc](https://github.com/TaceoLabs/oprf-service/commit/294b8bc94ae59135fed205957086adce4e99d4e1))
- Add back updated README ([#282](https://github.com/TaceoLabs/oprf-service/pull/282)) - ([f5bf211](https://github.com/TaceoLabs/oprf-service/commit/f5bf2115ab962d0725307fab8ad2fae16da65b27))

### 🐛 Bug Fixes


- Update deploy_oprf_key_registry to use bundled contracts ([#404](https://github.com/TaceoLabs/oprf-service/pull/404)) - ([fc78b22](https://github.com/TaceoLabs/oprf-service/commit/fc78b22ed0624519981d12eee7b455d50ccc2633))

### 🚜 Refactor


- *(test)* Removed oprf-test and deploy logic to test-utils - ([9c91eaa](https://github.com/TaceoLabs/oprf-service/commit/9c91eaa9c4119368e74fbb76a15b74fdaba7451c))
- [**breaking**] ShareEpoch is a u32 now ([#410](https://github.com/TaceoLabs/oprf-service/pull/410)) - ([2ba29f5](https://github.com/TaceoLabs/oprf-service/commit/2ba29f5b9119e4632dfd1cb195955ace77ebf632))
- Distinguish between revert and rpc errors and always fail again - ([543a472](https://github.com/TaceoLabs/oprf-service/commit/543a4728d670b3aec36c535b2e72f78d9fe46e85))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))

### 🧪 Testing


- Add test that parses invalid proof event from delegate call - ([bd24f2a](https://github.com/TaceoLabs/oprf-service/commit/bd24f2afa662d6a8a422b3a667d03ec78ad47aaf))
- Removed deps from test-utils to key-gen/service - ([4e349c9](https://github.com/TaceoLabs/oprf-service/commit/4e349c9b46e3d405cd4400fe127ba0df154525f0))
- [**breaking**] Added test setup and integration test-suites for key-gen + service - ([57b10fa](https://github.com/TaceoLabs/oprf-service/commit/57b10fa47eb3dc81cff6b96988fbbe7e99275080))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))
- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))

### Build


- *(ci)* Add e2e-test - ([e2ec385](https://github.com/TaceoLabs/oprf-service/commit/e2ec3857bbce5b41d2d19d6cbea253f46de9c5a5))

