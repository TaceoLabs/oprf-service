# Changelog

## [Unreleased]

## [0.7.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-service-v0.7.0...taceo-oprf-service-v0.7.1)

### ⚙️ Miscellaneous Tasks


- Updated the following local packages: taceo-oprf-types, taceo-oprf-test-utils - ([0000000](https://github.com/TaceoLabs/oprf-service/commit/0000000))


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

