# Changelog

## [Unreleased]

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

