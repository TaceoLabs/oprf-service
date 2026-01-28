# Changelog

## [Unreleased]

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

