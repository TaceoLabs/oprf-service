# Changelog

## [Unreleased]

## [0.7.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.7.0...taceo-oprf-client-v0.7.1)

### 🐛 Bug Fixes


- Only replace http once in client when building ws - ([7f73745](https://github.com/TaceoLabs/oprf-service/commit/7f73745bfd14ba1845d87db4f371023b321ac613))

### 🧪 Testing


- Add test-setup in oprf-client + dupl party id check - ([d15e566](https://github.com/TaceoLabs/oprf-service/commit/d15e5660bbcfe3a65e35e1f68054bac18832172f))


## [0.7.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.6.1...taceo-oprf-client-v0.7.0)

### ⛰️ Features


- [**breaking**] Add additional Error information to the case where not enough servers respond ([#464](https://github.com/TaceoLabs/oprf-service/pull/464)) - ([831928b](https://github.com/TaceoLabs/oprf-service/commit/831928bbce1e8b6356a56830d5aae3dde6e3cf4d))


## [0.6.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.6.0...taceo-oprf-client-v0.6.1)

### ⚙️ Miscellaneous Tasks


- Updated the following local packages: taceo-oprf-types - ([0000000](https://github.com/TaceoLabs/oprf-service/commit/0000000))


## [0.6.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.5.0...taceo-oprf-client-v0.6.0)

### 🚜 Refactor


- [**breaking**] Auth-module trait now returns the OPRF key id and removed from req ([#433](https://github.com/TaceoLabs/oprf-service/pull/433)) - ([1428e3d](https://github.com/TaceoLabs/oprf-service/commit/1428e3daf88b779838610e1e7b380b48293b006b))


## [0.5.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.4.0...taceo-oprf-client-v0.5.0)

### ⛰️ Features


- [**breaking**] Client filters retrieved sessions and continues with threshold many from same - ([0f3e783](https://github.com/TaceoLabs/oprf-service/commit/0f3e7831b6c077378ce43db1ea13f277d7fb549e))

### 🚜 Refactor


- Client now doesn't gracefully close the ws connections anymore - ([cc11858](https://github.com/TaceoLabs/oprf-service/commit/cc11858c071fc6cd2b4eda162570f888be209112))
- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### ⚙️ Miscellaneous Tasks


- Typo in log message - ([0d7902f](https://github.com/TaceoLabs/oprf-service/commit/0d7902f245dd65cc4364360209436575acc111c7))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.3.0...taceo-oprf-client-v0.4.0)

### ⛰️ Features


- [**breaking**] Add support for multiple OPRF modules per OPRF service ([#401](https://github.com/TaceoLabs/oprf-service/pull/401)) - ([eea5a1e](https://github.com/TaceoLabs/oprf-service/commit/eea5a1ef330cbe34beb50d6bc16f8526bf5399f7))

### 🚜 Refactor


- [**breaking**] Remove v1 concept - ([2fe5324](https://github.com/TaceoLabs/oprf-service/commit/2fe5324a2a85be97873fca0ff5a698b7d31451d4))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))
- Fixed docs - ([eff3fa3](https://github.com/TaceoLabs/oprf-service/commit/eff3fa39658a3e2f85061270bdfe834f2762d9e4))
- Removed blinding_factor re-export from client - ([32035b8](https://github.com/TaceoLabs/oprf-service/commit/32035b861caa8da2c9c7fe983ac951a6902cf6b0))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.2.0...taceo-oprf-client-v0.3.0)

### ⛰️ Features


- [**breaking**] Receive OprfPublicKey during distributed_oprf ([#366](https://github.com/TaceoLabs/oprf-service/pull/366)) - ([10eeb99](https://github.com/TaceoLabs/oprf-service/commit/10eeb999f2ab48f1ebe612b19745432c8239d73a))


## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-client-v0.1.0...taceo-oprf-client-v0.2.0)

### ⛰️ Features


- [**breaking**] Client needs to send used protocol version in header ([#361](https://github.com/TaceoLabs/oprf-service/pull/361)) - ([e43bced](https://github.com/TaceoLabs/oprf-service/commit/e43bcedd35fb37752107982cd5c873e80457c21c))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Add checks to ensure contributing parties are sorted and unique. - ([5dd4905](https://github.com/TaceoLabs/oprf-service/commit/5dd490517f774458ce11894174c45bcffc9dabdb))

### 🐛 Bug Fixes


- Better error message in ws read - ([23abab5](https://github.com/TaceoLabs/oprf-service/commit/23abab5ddcbe9d234996c730f780bff4b70f139e))
- Combine_proofs asks for contributing_parties - ([ea0354c](https://github.com/TaceoLabs/oprf-service/commit/ea0354c9577dcbccf4365c45ca3fdc9842bbf664))
- Lack of uniqueness check of party ID’s when computing lagrange - ([e98d9e3](https://github.com/TaceoLabs/oprf-service/commit/e98d9e35e6c06e999a7d90b4e75030c0929f8d13))

### ⚙️ Miscellaneous Tasks


- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))

