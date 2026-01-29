# Changelog

## [Unreleased]

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

