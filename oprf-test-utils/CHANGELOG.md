# Changelog

## [Unreleased]

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

