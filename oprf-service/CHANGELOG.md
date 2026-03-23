# Changelog

## [Unreleased]

## [0.11.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.10.1...taceo-oprf-service-v0.11.0)

### ⛰️ Features


- Feat(service,types)! added more fine-grained error codes - ([a8b95dd](https://github.com/TaceoLabs/oprf-service/commit/a8b95ddd3ea3b6df67f5b1e8f182a73a699f18ed))

### 🚜 Refactor


- *(node)* Updated log events - ([353d90c](https://github.com/TaceoLabs/oprf-service/commit/353d90c8b06d23ef7a3e71a9992b103623659ed7))

### ⚙️ Miscellaneous Tasks


- *(service)* Removed tracing element that was never recorded - ([0f21e62](https://github.com/TaceoLabs/oprf-service/commit/0f21e624bfce2ddc05d5e888d691a68889cecc3b))
- Pin old localstack version ([#527](https://github.com/TaceoLabs/oprf-service/pull/527)) - ([fed00a3](https://github.com/TaceoLabs/oprf-service/commit/fed00a3b083f125ea5e657f065ecbe047ee9ec71))
- Fixed a typo - ([5c21f6c](https://github.com/TaceoLabs/oprf-service/commit/5c21f6c83f1e39bbbd1a974e86cd400d59a071b7))
- Renamed example - ([82f2a6d](https://github.com/TaceoLabs/oprf-service/commit/82f2a6dd03e7ffe6f16668b09b7b2732aac0922f))


## [0.10.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.10.0...taceo-oprf-service-v0.10.1)

### 🐛 Bug Fixes


- Uses correct header name again ([#518](https://github.com/TaceoLabs/oprf-service/pull/518)) - ([4a2fd52](https://github.com/TaceoLabs/oprf-service/commit/4a2fd525d55c325456045edc1f0a86bccdb33dd1))


## [0.10.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.9.2...taceo-oprf-service-v0.10.0)

### 🚜 Refactor


- *(core)* [**breaking**] Enabled prod level clippy lints for core - ([52996dc](https://github.com/TaceoLabs/oprf-service/commit/52996dceac894ca3bdf7582d7e61806065790bfc))
- *(node)* [**breaking**] Removed error type from secret-manager for retry - ([f361b04](https://github.com/TaceoLabs/oprf-service/commit/f361b045543b195468849a483ccda3d5a8c42c88))
- *(node)* [**breaking**] Enabled prod level clippy lints for service - ([3f835a2](https://github.com/TaceoLabs/oprf-service/commit/3f835a24298aab9db54d8621cdfd9253df6cd2b0))
- *(test-utils)* [**breaking**] Refactor service_test_secret_manager macro - ([6bd6e27](https://github.com/TaceoLabs/oprf-service/commit/6bd6e2735191746061a199759f50f0f1e166c479))
- *(types)* [**breaking**] Enabled prod level clippy lints for types - ([7f97b0b](https://github.com/TaceoLabs/oprf-service/commit/7f97b0b53a4949bc36b022dadba6680abe9b3426))
- Removed health/info routes and uses nodes-common - ([ac1d534](https://github.com/TaceoLabs/oprf-service/commit/ac1d534258c0675e2bd0ee4fcfbe5becdb7e21c7))
- [**breaking**] Move from clap to config [TAC-475] ([#506](https://github.com/TaceoLabs/oprf-service/pull/506)) - ([d33a65b](https://github.com/TaceoLabs/oprf-service/commit/d33a65bdce4d3dcc7c2f4067be52313b8f470447))

### 🧪 Testing


- Updated runtime for tokio::test - ([7383204](https://github.com/TaceoLabs/oprf-service/commit/7383204fb460acdc13709c1b4fdec31077192888))

### ⚙️ Miscellaneous Tasks


- Small fixes to allow compat for downstream ([#514](https://github.com/TaceoLabs/oprf-service/pull/514)) - ([a39850d](https://github.com/TaceoLabs/oprf-service/commit/a39850de605376c0493507d958c2ae605b62e269))


## [0.9.2](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.9.1...taceo-oprf-service-v0.9.2)

### ⛰️ Features


- *(oprf-client)* Add WASM WebSocket support via gloo-net ([#488](https://github.com/TaceoLabs/oprf-service/pull/488)) - ([7fa5961](https://github.com/TaceoLabs/oprf-service/commit/7fa59613fca491f1ea96b2d2b0836772a1ccde31))


## [0.9.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.9.0...taceo-oprf-service-v0.9.1)

### ⛰️ Features


- Added possibility to send client version as query param ([#490](https://github.com/TaceoLabs/oprf-service/pull/490)) - ([7f807f2](https://github.com/TaceoLabs/oprf-service/commit/7f807f20c55a25afad167d58c332e1b1b05fd7e3))

### 📚 Documentation


- Update Readme to reflect state of repository. ([#494](https://github.com/TaceoLabs/oprf-service/pull/494)) - ([4cb63b0](https://github.com/TaceoLabs/oprf-service/commit/4cb63b02f4615bdb1c3a7cf90d61828b5daf439e))

### ⚙️ Miscellaneous Tasks


- Removed three postgres instances from e2e-test ([#486](https://github.com/TaceoLabs/oprf-service/pull/486)) - ([ffd8f81](https://github.com/TaceoLabs/oprf-service/commit/ffd8f8133a03ee288f039566490e6bca21681395))


## [0.9.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.8.0...taceo-oprf-service-v0.9.0)

### ⛰️ Features


- Emit I-am-alive metrics for key-gen and service ([#476](https://github.com/TaceoLabs/oprf-service/pull/476)) - ([382c923](https://github.com/TaceoLabs/oprf-service/commit/382c92394feeef30ca926c54d003913239f11c78))


## [0.8.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.7.1...taceo-oprf-service-v0.8.0)

### 🚜 Refactor


- [**breaking**] Removed region from config + endpoint - ([f3bb057](https://github.com/TaceoLabs/oprf-service/commit/f3bb057784d415baf575c8991be295e4f5176924))
- Some more tracing cleanup in key_event_watchers - ([84a73ce](https://github.com/TaceoLabs/oprf-service/commit/84a73ce89d11586c44a06c39964e7860b4b9ae22))
- Tracing clarity restructure - ([22c4c68](https://github.com/TaceoLabs/oprf-service/commit/22c4c68c183db344bc590bb7f0be6fe2bdcfc6eb))

### 🧪 Testing


- Add exhaustive tests for node ([#456](https://github.com/TaceoLabs/oprf-service/pull/456)) - ([cb42ef9](https://github.com/TaceoLabs/oprf-service/commit/cb42ef99722da5a56944ced275fde42ae508776e))

### ⚙️ Miscellaneous Tasks


- Added auth counter metric from other repo - ([0c8def2](https://github.com/TaceoLabs/oprf-service/commit/0c8def2a0815f5634251b420b3b31edc18997447))
- Created span for refresh task - ([1d69f80](https://github.com/TaceoLabs/oprf-service/commit/1d69f8020667638f5b1e5eeba3fd2a73f3462014))


## [0.7.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.7.0...taceo-oprf-service-v0.7.1)

### 🚜 Refactor


- Removed ready check + log close reason for key-event-watcher - ([31cc24f](https://github.com/TaceoLabs/oprf-service/commit/31cc24fcb757d7e743b7e51875a8a2a5cb2c95ca))


## [0.7.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.6.0...taceo-oprf-service-v0.7.0)

### ⛰️ Features


- [**breaking**] Add task that periodically refreshes shares for nodes - ([68a0344](https://github.com/TaceoLabs/oprf-service/commit/68a034422c75bfab4b21641a4e3acc76803e8cd9))

### 🐛 Bug Fixes


- Key-material-store refuses to roll back when older share ([#445](https://github.com/TaceoLabs/oprf-service/pull/445)) - ([11ff80f](https://github.com/TaceoLabs/oprf-service/commit/11ff80fbcbe2af56b819c84c3afc2dd3becb8297))

### 🚜 Refactor


- Uses soft delete over hard delete of shares now - ([319fc77](https://github.com/TaceoLabs/oprf-service/commit/319fc77b5a17dd4c8b1de2235d378d9b2d99db96))
- [**breaking**] Cleanup (remarks DK) - ([ec2a3de](https://github.com/TaceoLabs/oprf-service/commit/ec2a3defa6bc5e01bafd595628d2add281885e35))
- [**breaking**] Uses constant backoff for DB queries in service/key-gen - ([cf919d0](https://github.com/TaceoLabs/oprf-service/commit/cf919d0e49222c363b5cb9a18b2c45fd3358a415))
- [**breaking**] Make max_db_connections + acquire timeout configureable - ([db4167a](https://github.com/TaceoLabs/oprf-service/commit/db4167a08b1b4e5d3e05b92c0b154027aa95c040))
- Make poll interval configurable from oprf-node to secret-manager - ([381126e](https://github.com/TaceoLabs/oprf-service/commit/381126e6578359f963f5d7f650c37a72ffd76ff1))

### 🧪 Testing


- Added unit tests for delete in oprf-service - ([a4606c6](https://github.com/TaceoLabs/oprf-service/commit/a4606c62a96e5a44f3e7c3663d06f4d2529a4dde))

### ⚙️ Miscellaneous Tasks


- Renamed paramater name in reload - ([4496d05](https://github.com/TaceoLabs/oprf-service/commit/4496d05fc80f8a6c798f898f566ab9c4924c093b))


## [0.6.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.5.0...taceo-oprf-service-v0.6.0)

### 🐛 Bug Fixes


- Prevents empty schema name for postgres secret-manager ([#423](https://github.com/TaceoLabs/oprf-service/pull/423)) - ([b71d25a](https://github.com/TaceoLabs/oprf-service/commit/b71d25a88f58728f0548d12bd27e04d9c4c2528d))

### 🚜 Refactor


- [**breaking**] Auth-module trait now returns the OPRF key id and removed from req ([#433](https://github.com/TaceoLabs/oprf-service/pull/433)) - ([1428e3d](https://github.com/TaceoLabs/oprf-service/commit/1428e3daf88b779838610e1e7b380b48293b006b))
- [**breaking**] Removed StartedServices and moved to nodes-common ([#431](https://github.com/TaceoLabs/oprf-service/pull/431)) - ([c3d065e](https://github.com/TaceoLabs/oprf-service/commit/c3d065e7dd17ee6ddde756c18498d12e50d66cc0))

### 🧪 Testing


- More tests for key-gen event watcher - ([78727c5](https://github.com/TaceoLabs/oprf-service/commit/78727c5dc9be57ebcf814694b6752efaee28ba4b))


## [0.5.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.4.0...taceo-oprf-service-v0.5.0)

### ⛰️ Features


- Make namespace configurable for postgres secret-manager - ([44474ab](https://github.com/TaceoLabs/oprf-service/commit/44474aba5efe8c159ed334aff72bbf0d4edae6e6))
- Add postgres secret-manager in service - ([3f920bd](https://github.com/TaceoLabs/oprf-service/commit/3f920bd890aea3b0307587d7851cdeaa5d82b4b7))

### 🐛 Bug Fixes


- Fixes an endless loop bug in an async task - ([5092e31](https://github.com/TaceoLabs/oprf-service/commit/5092e317a0de9a65dfa1d86a40d0adc12394117d))

### 🚜 Refactor


- Moved migrations to key-gen folder - ([7b040cb](https://github.com/TaceoLabs/oprf-service/commit/7b040cba208a15985a71d69e13f2ffbe470f9ad1))
- Move some configs to inner config - ([a1d436d](https://github.com/TaceoLabs/oprf-service/commit/a1d436dda4f4f69da704ddbc04f45d2dd6616f9e))
- Client now doesn't gracefully close the ws connections anymore - ([cc11858](https://github.com/TaceoLabs/oprf-service/commit/cc11858c071fc6cd2b4eda162570f888be209112))
- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))
- Add zeroise on drop for ShareRow - ([c4b4588](https://github.com/TaceoLabs/oprf-service/commit/c4b45880f97f468d55c6c9c1170b72cdb497603b))
- [**breaking**] Switched secret-manager impl in key-gen/example-service - ([7706dfb](https://github.com/TaceoLabs/oprf-service/commit/7706dfb14278839b1f4c677711e9bf761c88f056))
- [**breaking**] Load address from secret-manager over config - ([7838777](https://github.com/TaceoLabs/oprf-service/commit/78387771c268c5f18b7331f825cb2fc1a16438fc))
- Added some public methods for key-material store - ([f768dbf](https://github.com/TaceoLabs/oprf-service/commit/f768dbf004fd66af43d933b34d40b6f26a309703))
- [**breaking**] Updated secret-manager trait for service - ([c134442](https://github.com/TaceoLabs/oprf-service/commit/c1344427327b0bd5176491839ec4c7c42d2b547d))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### 🧪 Testing


- Fixes the test for schema integrations - ([6c43f15](https://github.com/TaceoLabs/oprf-service/commit/6c43f151c0278d7bb5712eec3f1511d94191f113))
- Moved secret-manager to unit tests again - ([873bc72](https://github.com/TaceoLabs/oprf-service/commit/873bc725db46e29c3dfc5a7131bac535229ea06f))
- Add test for load_address for postgres secret-manager - ([c39a316](https://github.com/TaceoLabs/oprf-service/commit/c39a3164cbc507cd50fc70a850df1dd4a79da67f))
- Add tests for postgres secret-manager in service - ([15c47f5](https://github.com/TaceoLabs/oprf-service/commit/15c47f591a5fefc05a9b72becb90d4140d1587f4))

### ⚙️ Miscellaneous Tasks


- Fixed a log message - ([2b8b3d6](https://github.com/TaceoLabs/oprf-service/commit/2b8b3d60dfdfbe359dd389f58c424973b2a8fdbf))
- Update docs and typos - ([7031b3c](https://github.com/TaceoLabs/oprf-service/commit/7031b3cb846a6799aa5fe0aea07719b21d7c85d1))

### Build


- *(deps)* Use tls-rustls-aws-lc-rs feature for sqlx - ([3723c12](https://github.com/TaceoLabs/oprf-service/commit/3723c12cf9853a35d35b971ed2aa4e50e6f60f36))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.3.0...taceo-oprf-service-v0.4.0)

### ⛰️ Features


- Move TestSecretManager trait impls to oprf-test-utils again ([#407](https://github.com/TaceoLabs/oprf-service/pull/407)) - ([76ad208](https://github.com/TaceoLabs/oprf-service/commit/76ad208206bd6594b4361e956e2835740595334c))
- [**breaking**] Add support for multiple OPRF modules per OPRF service ([#401](https://github.com/TaceoLabs/oprf-service/pull/401)) - ([eea5a1e](https://github.com/TaceoLabs/oprf-service/commit/eea5a1ef330cbe34beb50d6bc16f8526bf5399f7))
- Add metric for OprfRequestAuth verify time ([#389](https://github.com/TaceoLabs/oprf-service/pull/389)) - ([45c48fa](https://github.com/TaceoLabs/oprf-service/commit/45c48fa80ec842c660421be71ef480535c0c1cf2))

### 🚜 Refactor


- Removed example crates - ([23479d8](https://github.com/TaceoLabs/oprf-service/commit/23479d88042d8239381a258d86db441235c3e554))
- Added example oprf-service/dev-client - ([0398347](https://github.com/TaceoLabs/oprf-service/commit/0398347e0bfefaf67d4d88d169cfe094a78545a8))
- [**breaking**] Remove v1 concept - ([2fe5324](https://github.com/TaceoLabs/oprf-service/commit/2fe5324a2a85be97873fca0ff5a698b7d31451d4))
- [**breaking**] Moved Auth trait definition to types-crate - ([d7aa19f](https://github.com/TaceoLabs/oprf-service/commit/d7aa19ffe82b4e175390c8e9afb21bd82878c206))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))

### 📚 Documentation


- Fix capitalization of TACEO:OPRF - ([181f2cd](https://github.com/TaceoLabs/oprf-service/commit/181f2cd7dc14d3d5383a7a2deaf8c57953c4302a))
- Updated docs after moving the auth service - ([5a071d1](https://github.com/TaceoLabs/oprf-service/commit/5a071d1a16f373333c1eaae27f77cd6ce8fde53e))
- Fixed two typos ([#402](https://github.com/TaceoLabs/oprf-service/pull/402)) - ([5bcee05](https://github.com/TaceoLabs/oprf-service/commit/5bcee0536320eb92c7e189531c200259b5ad46ec))

### 🧪 Testing


- Removed deps from test-utils to key-gen/service - ([4e349c9](https://github.com/TaceoLabs/oprf-service/commit/4e349c9b46e3d405cd4400fe127ba0df154525f0))
- [**breaking**] Added test setup and integration test-suites for key-gen + service - ([57b10fa](https://github.com/TaceoLabs/oprf-service/commit/57b10fa47eb3dc81cff6b96988fbbe7e99275080))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.2.0...taceo-oprf-service-v0.3.0)

### ⛰️ Features


- Improve oprf-service WS error responses [TAC-112] ([#380](https://github.com/TaceoLabs/oprf-service/pull/380)) - ([abfd9d6](https://github.com/TaceoLabs/oprf-service/commit/abfd9d6c14673efdfc641b75c6e59b1341044f57))
- Emit METRICS_ID_NODE_OPRF_SECRETS metric ([#384](https://github.com/TaceoLabs/oprf-service/pull/384)) - ([31f7720](https://github.com/TaceoLabs/oprf-service/commit/31f77206b7ccd8089d19d7b7d9bff4091a126a7d))
- [**breaking**] Fix number of share in OprfKeyMaterial to 2 ([#377](https://github.com/TaceoLabs/oprf-service/pull/377)) - ([d5e08b5](https://github.com/TaceoLabs/oprf-service/commit/d5e08b5fe5b7b08494f14269175627c1e9a59532))
- Added region route to oprf_nodes ([#379](https://github.com/TaceoLabs/oprf-service/pull/379)) - ([dc88acc](https://github.com/TaceoLabs/oprf-service/commit/dc88acc980423678f809df3211a24c17a44c380a))
- [**breaking**] Receive OprfPublicKey during distributed_oprf ([#366](https://github.com/TaceoLabs/oprf-service/pull/366)) - ([10eeb99](https://github.com/TaceoLabs/oprf-service/commit/10eeb999f2ab48f1ebe612b19745432c8239d73a))

### 🚜 Refactor


- [**breaking**] Update rust contract interface with new changes related to Library improvements - ([0ee6043](https://github.com/TaceoLabs/oprf-service/commit/0ee604395f48307e3bc4d8f7f899da35b64518fc))


## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.1.0...taceo-oprf-service-v0.2.0)

### ⛰️ Features


- [**breaking**] Client needs to send used protocol version in header ([#361](https://github.com/TaceoLabs/oprf-service/pull/361)) - ([e43bced](https://github.com/TaceoLabs/oprf-service/commit/e43bcedd35fb37752107982cd5c873e80457c21c))
- Emit and add more metrics for oprf-node and oprf-key-gen ([#350](https://github.com/TaceoLabs/oprf-service/pull/350)) - ([d36e2d4](https://github.com/TaceoLabs/oprf-service/commit/d36e2d4c86f7d36d7837e708bf290815c61272a1))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Add checks to ensure contributing parties are sorted and unique. - ([5dd4905](https://github.com/TaceoLabs/oprf-service/commit/5dd490517f774458ce11894174c45bcffc9dabdb))

### 🐛 Bug Fixes


- Started services now waits until event watcher started before sending 200 in key-gen - ([68dfe04](https://github.com/TaceoLabs/oprf-service/commit/68dfe0444a54a69a5ce67afce3f07a9ff62d0712))
- Started services now waits until all services started before sending 200 - ([7d2cd1e](https://github.com/TaceoLabs/oprf-service/commit/7d2cd1e4924cf2400ea811b35bffa920eadcd4e0))

### ⚙️ Miscellaneous Tasks


- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))

### Build


- *(deps)* Update alloy to 1.4.0 ([#356](https://github.com/TaceoLabs/oprf-service/pull/356)) - ([fcdfaf4](https://github.com/TaceoLabs/oprf-service/commit/fcdfaf4395a55b081f2b50132cb5cb6081036659))

