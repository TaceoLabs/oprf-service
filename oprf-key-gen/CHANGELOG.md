# Changelog

## [Unreleased]

## [0.4.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-key-gen-v0.4.0...taceo-oprf-key-gen-v0.4.1)

### 🐛 Bug Fixes


- Handle revert reasons during key-gen more gracefully ([#451](https://github.com/TaceoLabs/oprf-service/pull/451)) - ([d16321c](https://github.com/TaceoLabs/oprf-service/commit/d16321c98fde0aa1ed30aa380f0700baf6e91c1c))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-key-gen-v0.3.0...taceo-oprf-key-gen-v0.4.0)

### ⛰️ Features


- [**breaking**] Ping secret-manager to wake up from deep-sleep when doing key-gen ([#447](https://github.com/TaceoLabs/oprf-service/pull/447)) - ([e01827b](https://github.com/TaceoLabs/oprf-service/commit/e01827bbd5c6f1ccdb24389f6fedec81135eb479))

### 🚜 Refactor


- Uses soft delete over hard delete of shares now - ([319fc77](https://github.com/TaceoLabs/oprf-service/commit/319fc77b5a17dd4c8b1de2235d378d9b2d99db96))
- [**breaking**] Cleanup (remarks DK) - ([ec2a3de](https://github.com/TaceoLabs/oprf-service/commit/ec2a3defa6bc5e01bafd595628d2add281885e35))
- [**breaking**] Uses constant backoff for DB queries in service/key-gen - ([cf919d0](https://github.com/TaceoLabs/oprf-service/commit/cf919d0e49222c363b5cb9a18b2c45fd3358a415))
- [**breaking**] Make max_db_connections + acquire timeout configureable - ([db4167a](https://github.com/TaceoLabs/oprf-service/commit/db4167a08b1b4e5d3e05b92c0b154027aa95c040))

### 🧪 Testing


- Added unit tests for delete in oprf-service - ([a4606c6](https://github.com/TaceoLabs/oprf-service/commit/a4606c62a96e5a44f3e7c3663d06f4d2529a4dde))
- Added delete test in dev-client - ([abd576f](https://github.com/TaceoLabs/oprf-service/commit/abd576f4bc20fcb49ae9449b9254006e82347a41))

### ⚙️ Miscellaneous Tasks


- Reduce default transaction confirmations to 5 - ([9043369](https://github.com/TaceoLabs/oprf-service/commit/90433695c61c2ff53e90cff9a03698be5b157a4a))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-key-gen-v0.2.0...taceo-oprf-key-gen-v0.3.0)

### 🐛 Bug Fixes


- Prevents empty schema name for postgres secret-manager ([#423](https://github.com/TaceoLabs/oprf-service/pull/423)) - ([b71d25a](https://github.com/TaceoLabs/oprf-service/commit/b71d25a88f58728f0548d12bd27e04d9c4c2528d))

### 🚜 Refactor


- [**breaking**] Removed StartedServices and moved to nodes-common ([#431](https://github.com/TaceoLabs/oprf-service/pull/431)) - ([c3d065e](https://github.com/TaceoLabs/oprf-service/commit/c3d065e7dd17ee6ddde756c18498d12e50d66cc0))
- Moved tcp-listener in key-gen to axum task - ([81c9ea1](https://github.com/TaceoLabs/oprf-service/commit/81c9ea1de8294750a9c3a8d2d64102e0957a7ae8))
- Key-gen tasks now propagte error to callsite if they crash - ([46e51df](https://github.com/TaceoLabs/oprf-service/commit/46e51dfb1d194c27d8330631e8127d7e0a01a79d))
- Remove unnecessary check as we check that at callsite as well - ([b2d97d6](https://github.com/TaceoLabs/oprf-service/commit/b2d97d66a580b1de0795a164417f586d4f3f4698))
- [**breaking**] Key-gen lib now only spawns tasks/axum router and we expect - ([7d91c6e](https://github.com/TaceoLabs/oprf-service/commit/7d91c6e78421f9563a0bbfca01fd6ce144452836))

### 📚 Documentation


- Fixes broken docs - ([9f5f0e4](https://github.com/TaceoLabs/oprf-service/commit/9f5f0e4629e3205704c988dbcf42bc6e227eeec3))

### 🧪 Testing


- More tests for key-gen event watcher - ([78727c5](https://github.com/TaceoLabs/oprf-service/commit/78727c5dc9be57ebcf814694b6752efaee28ba4b))
- Added more tests to key-gen test suite - ([d7db1df](https://github.com/TaceoLabs/oprf-service/commit/d7db1dffdf2bb13d498eff69dc5cdf60f643a6a6))
- Updated test-setup for key-gen and added axum tests - ([ae246b5](https://github.com/TaceoLabs/oprf-service/commit/ae246b5b895ea2228fc25c44e105b616ac55e95b))

### ⚙️ Miscellaneous Tasks


- Removed debug logs from test - ([fc51577](https://github.com/TaceoLabs/oprf-service/commit/fc515774a830baba23f6fddbec0d6650deef104b))


## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-key-gen-v0.1.0...taceo-oprf-key-gen-v0.2.0)

### ⛰️ Features


- Make namespace configurable for postgres secret-manager - ([44474ab](https://github.com/TaceoLabs/oprf-service/commit/44474aba5efe8c159ed334aff72bbf0d4edae6e6))
- Add postgres secret-manager in service - ([3f920bd](https://github.com/TaceoLabs/oprf-service/commit/3f920bd890aea3b0307587d7851cdeaa5d82b4b7))
- Handle not-enough-producers event - ([6194270](https://github.com/TaceoLabs/oprf-service/commit/6194270f93f4eace48c31bf6be559d59b5ae3746))
- Add postgres/aws combination for secret-manager - ([e02f690](https://github.com/TaceoLabs/oprf-service/commit/e02f6906c7c17f62fee4b0eb5386053588520bde))

### 🚜 Refactor


- Moved migrations to key-gen folder - ([7b040cb](https://github.com/TaceoLabs/oprf-service/commit/7b040cba208a15985a71d69e13f2ffbe470f9ad1))
- Move some configs to inner config - ([a1d436d](https://github.com/TaceoLabs/oprf-service/commit/a1d436dda4f4f69da704ddbc04f45d2dd6616f9e))
- [**breaking**] Reworked get_previous_share to get_share_by_epoch and updated callsite - ([8a2c100](https://github.com/TaceoLabs/oprf-service/commit/8a2c10005eaef9a37e4a0243981a77e75eda0d03))
- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))
- [**breaking**] Switched secret-manager impl in key-gen/example-service - ([7706dfb](https://github.com/TaceoLabs/oprf-service/commit/7706dfb14278839b1f4c677711e9bf761c88f056))
- [**breaking**] Load address from secret-manager over config - ([7838777](https://github.com/TaceoLabs/oprf-service/commit/78387771c268c5f18b7331f825cb2fc1a16438fc))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### 🧪 Testing


- Fixes the test for schema integrations - ([6c43f15](https://github.com/TaceoLabs/oprf-service/commit/6c43f151c0278d7bb5712eec3f1511d94191f113))
- Fixed tests again - ([a2fbc6b](https://github.com/TaceoLabs/oprf-service/commit/a2fbc6b81e191e28abbc7d128cf60c7031bcee8a))
- Moved secret-manager to unit tests again - ([873bc72](https://github.com/TaceoLabs/oprf-service/commit/873bc725db46e29c3dfc5a7131bac535229ea06f))
- Add tests for postgres secret-manager in service - ([15c47f5](https://github.com/TaceoLabs/oprf-service/commit/15c47f591a5fefc05a9b72becb90d4140d1587f4))
- Restructure for the and moved testcontainer to test-utils - ([e5fb5b9](https://github.com/TaceoLabs/oprf-service/commit/e5fb5b901bb1b832878a47f010ab0abfa3486496))

### ⚙️ Miscellaneous Tasks


- *(test)* Renamed eth_private_key/eth_address to TEST_* to highlight that those are test keys - ([b3b95bf](https://github.com/TaceoLabs/oprf-service/commit/b3b95bfbc3bec66181ee0ea251f99364c41c52a6))
- Fixed typo in docs - ([c3532a2](https://github.com/TaceoLabs/oprf-service/commit/c3532a232871976f032d94c1d6d2e1603086770f))
- Fixed typo - ([a7863f4](https://github.com/TaceoLabs/oprf-service/commit/a7863f4dee9d04d9b6489ed4cc026f8743a55ad0))
- Added some more metrics for (blob) gas price - ([229d14d](https://github.com/TaceoLabs/oprf-service/commit/229d14dc9edab8e40ea52a9679a470cf8f4f91cc))
- Added default-value for postgres connection string - ([4804625](https://github.com/TaceoLabs/oprf-service/commit/480462576c696dcb9c7193982e690415a0149b88))

### Build


- *(deps)* Use tls-rustls-aws-lc-rs feature for sqlx - ([3723c12](https://github.com/TaceoLabs/oprf-service/commit/3723c12cf9853a35d35b971ed2aa4e50e6f60f36))


## [0.1.0]

### ⛰️ Features


- Handle revert errors from contract gracefully - ([e41fdf3](https://github.com/TaceoLabs/oprf-service/commit/e41fdf398d9a23f67c1e63fa0d4ddf7294246da7))
- Move TestSecretManager trait impls to oprf-test-utils again ([#407](https://github.com/TaceoLabs/oprf-service/pull/407)) - ([76ad208](https://github.com/TaceoLabs/oprf-service/commit/76ad208206bd6594b4361e956e2835740595334c))
- [**breaking**] Add confirmation/max gas costs + metrics for gas cost - ([ba59ff0](https://github.com/TaceoLabs/oprf-service/commit/ba59ff00d56e9cb12a5f5c4909363f2897f6f720))
- Handle keygen abort events in key-gen [TAC-132] ([#368](https://github.com/TaceoLabs/oprf-service/pull/368)) - ([469d8f2](https://github.com/TaceoLabs/oprf-service/commit/469d8f2c52c9d04055daa1ee2399fb03bfd49f7b))
- Add logs and metrics for oprf-key-gen wallet balance [TAC-118] ([#382](https://github.com/TaceoLabs/oprf-service/pull/382)) - ([2cf3ac1](https://github.com/TaceoLabs/oprf-service/commit/2cf3ac11da6ba923d46c298b9a3d65a60f871308))
- [**breaking**] Fix number of share in OprfKeyMaterial to 2 ([#377](https://github.com/TaceoLabs/oprf-service/pull/377)) - ([d5e08b5](https://github.com/TaceoLabs/oprf-service/commit/d5e08b5fe5b7b08494f14269175627c1e9a59532))
- Adds nonce to TransactionConfirmation and robustness that key-gens don't die when replicated - ([6635eb2](https://github.com/TaceoLabs/oprf-service/commit/6635eb2072be422c39bbd241c4807cb47f682813))
- [**breaking**] Nodes can register as consumers in reshare - ([c9455f9](https://github.com/TaceoLabs/oprf-service/commit/c9455f953577b25addc5157475d030419d9d66d5))
- Emit and add more metrics for oprf-node and oprf-key-gen ([#350](https://github.com/TaceoLabs/oprf-service/pull/350)) - ([d36e2d4](https://github.com/TaceoLabs/oprf-service/commit/d36e2d4c86f7d36d7837e708bf290815c61272a1))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Robustness for key-gen and null responses ([#313](https://github.com/TaceoLabs/oprf-service/pull/313)) - ([7267f96](https://github.com/TaceoLabs/oprf-service/commit/7267f966049521abecc46c7a5513c1968df76958))
- Use updated version_info macro of nodes-helpers crate - ([683d4c6](https://github.com/TaceoLabs/oprf-service/commit/683d4c64901d5682cd6eb0cafa5e7a78092591e1))
- Add axum server with health and info route to oprf key gen - ([5082766](https://github.com/TaceoLabs/oprf-service/commit/508276671f35de8b390681d0c73350e12ebf18e5))
- Add threshold 2 num_peers 5 support and test ([#298](https://github.com/TaceoLabs/oprf-service/pull/298)) - ([887b656](https://github.com/TaceoLabs/oprf-service/commit/887b6564ea4a75a6d4b66959930005aedb1ddd11))
- Add re-randomization/reshare  ([#293](https://github.com/TaceoLabs/oprf-service/pull/293)) - ([5d6aea4](https://github.com/TaceoLabs/oprf-service/commit/5d6aea452f1dac05068836f827fa5bb0803b3cb5))
- Uses simple-nonce manager for key-gen ([#297](https://github.com/TaceoLabs/oprf-service/pull/297)) - ([1dbbc50](https://github.com/TaceoLabs/oprf-service/commit/1dbbc505fb22fad4d35d63f22bac71b122fb9765))
- [**breaking**] Split into oprf-key-gen and oprf-service ([#291](https://github.com/TaceoLabs/oprf-service/pull/291)) - ([294b8bc](https://github.com/TaceoLabs/oprf-service/commit/294b8bc94ae59135fed205957086adce4e99d4e1))
- Add back updated README ([#282](https://github.com/TaceoLabs/oprf-service/pull/282)) - ([f5bf211](https://github.com/TaceoLabs/oprf-service/commit/f5bf2115ab962d0725307fab8ad2fae16da65b27))

### 🐛 Bug Fixes


- [**breaking**] Now uses u8 over usize for max_epoch_cache_size ([#360](https://github.com/TaceoLabs/oprf-service/pull/360)) - ([2ada8ad](https://github.com/TaceoLabs/oprf-service/commit/2ada8ad32ffed952071b51431c9a8f613a7f5bce))
- Started services now waits until event watcher started before sending 200 in key-gen - ([68dfe04](https://github.com/TaceoLabs/oprf-service/commit/68dfe0444a54a69a5ce67afce3f07a9ff62d0712))
- Reattempts to send transactions to chain on null resp ([#306](https://github.com/TaceoLabs/oprf-service/pull/306)) - ([7f13d32](https://github.com/TaceoLabs/oprf-service/commit/7f13d32f7339896c37c75eaf2d2b349ed3f3a69c))

### 🚜 Refactor


- Distinguish between revert and rpc errors and always fail again - ([543a472](https://github.com/TaceoLabs/oprf-service/commit/543a4728d670b3aec36c535b2e72f78d9fe46e85))
- Decode events for key-event handler outside of handle methods - ([71e564f](https://github.com/TaceoLabs/oprf-service/commit/71e564fcf3e07953e83c9786d1e620086201c2aa))
- [**breaking**] Key-gen needs to provide listener from binary - ([953c7f5](https://github.com/TaceoLabs/oprf-service/commit/953c7f50fa394050f262b0de81b51e9a134a0bb3))
- Now return an error if ungraceful shutdown ([#391](https://github.com/TaceoLabs/oprf-service/pull/391)) - ([574ed04](https://github.com/TaceoLabs/oprf-service/commit/574ed04bf6514d966acc2c381a7cd5eec6ac04ca))
- Add filter for KeyGenConfirmation for party ID ([#390](https://github.com/TaceoLabs/oprf-service/pull/390)) - ([773d8b5](https://github.com/TaceoLabs/oprf-service/commit/773d8b5b5ae74333de334cadc07ad31508033928))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))
- [**breaking**] Update rust contract interface with new changes related to Library improvements - ([0ee6043](https://github.com/TaceoLabs/oprf-service/commit/0ee604395f48307e3bc4d8f7f899da35b64518fc))
- Reverts nonce confirmation again - ([adb4245](https://github.com/TaceoLabs/oprf-service/commit/adb4245249403254d5d3a063039ac9173eb24e7d))

### 📚 Documentation


- Fix capitalization of TACEO:OPRF - ([181f2cd](https://github.com/TaceoLabs/oprf-service/commit/181f2cd7dc14d3d5383a7a2deaf8c57953c4302a))
- Update docs - ([e7b5e7a](https://github.com/TaceoLabs/oprf-service/commit/e7b5e7a496eec7566e57a0e7c625fe5b2b79c97b))

### 🧪 Testing


- Add test that parses invalid proof event from delegate call - ([bd24f2a](https://github.com/TaceoLabs/oprf-service/commit/bd24f2afa662d6a8a422b3a667d03ec78ad47aaf))
- Removed deps from test-utils to key-gen/service - ([4e349c9](https://github.com/TaceoLabs/oprf-service/commit/4e349c9b46e3d405cd4400fe127ba0df154525f0))
- [**breaking**] Added test setup and integration test-suites for key-gen + service - ([57b10fa](https://github.com/TaceoLabs/oprf-service/commit/57b10fa47eb3dc81cff6b96988fbbe7e99275080))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))
- Naming to better highlight type in success receipt check - ([a6b774d](https://github.com/TaceoLabs/oprf-service/commit/a6b774d1941a23c0e9fb8ee9ee1c9e24af42e617))
- Fixed some tracing problems in aws secret-manager - ([29b10ab](https://github.com/TaceoLabs/oprf-service/commit/29b10aba4c35ab764b076859d9feb11a907a3b54))
- Don't publish taceo_oprf_key_gen for now ([#364](https://github.com/TaceoLabs/oprf-service/pull/364)) - ([3a46885](https://github.com/TaceoLabs/oprf-service/commit/3a4688540e0cebb418aaf400affc33dd8b097797))
- Prepare taceo-oprf-key-gen for publish ([#362](https://github.com/TaceoLabs/oprf-service/pull/362)) - ([2b51b66](https://github.com/TaceoLabs/oprf-service/commit/2b51b669f57519b151c10c2c546cc50d50c6623e))
- Update oprf-key-gen/src/services/key_event_watcher type - ([773109d](https://github.com/TaceoLabs/oprf-service/commit/773109d05eb7f8e87c455127eb87583346c8ed18))
- Enforces max_cache_size is not lower than 2 - ([12632b1](https://github.com/TaceoLabs/oprf-service/commit/12632b18de7c585bc2af678a9807840a76911d3a))
- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))
- [**breaking**] Prepare for publish ([#318](https://github.com/TaceoLabs/oprf-service/pull/318)) - ([e09a6b1](https://github.com/TaceoLabs/oprf-service/commit/e09a6b1f42749c879a9546d07f15b5df93cdd354))
- Add span recording in key-event watcher ([#304](https://github.com/TaceoLabs/oprf-service/pull/304)) - ([38c070a](https://github.com/TaceoLabs/oprf-service/commit/38c070a1c53924f83232958864646049b317308d))

### Build


- *(deps)* Update alloy to 1.4.0 ([#356](https://github.com/TaceoLabs/oprf-service/pull/356)) - ([fcdfaf4](https://github.com/TaceoLabs/oprf-service/commit/fcdfaf4395a55b081f2b50132cb5cb6081036659))

