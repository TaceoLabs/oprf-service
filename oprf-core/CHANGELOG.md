# Changelog

## [Unreleased]

## [0.4.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-core-v0.4.0...taceo-oprf-core-v0.4.1)

### ⛰️ Features


- Added CanonicalSerialize/Deserialize for DB storage - ([efcde52](https://github.com/TaceoLabs/oprf-service/commit/efcde524532fe4575ded5f87f3eb3777feec66fd))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-core-v0.3.0...taceo-oprf-core-v0.4.0)

### ⛰️ Features


- Add a way to construct a BlindingFactor directly ([#408](https://github.com/TaceoLabs/oprf-service/pull/408)) - ([8d405ca](https://github.com/TaceoLabs/oprf-service/commit/8d405cab265ff21c595c9d8810d878e14144e4e5))

### 🚜 Refactor


- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))

### 📚 Documentation


- Fix invalid return value in Rustdoc - ([c179645](https://github.com/TaceoLabs/oprf-service/commit/c1796450837bbd49c36fc9410d32d0ef6c1c7bc6))

### 🧪 Testing


- Fix broken benchmark file - ([1e07a8e](https://github.com/TaceoLabs/oprf-service/commit/1e07a8e50c61739bc59ba5f0f5e20426aade9bdc))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-core-v0.2.0...taceo-oprf-core-v0.3.0)

### ⛰️ Features


- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Add checks to ensure contributing parties are sorted and unique. - ([5dd4905](https://github.com/TaceoLabs/oprf-service/commit/5dd490517f774458ce11894174c45bcffc9dabdb))

### 🐛 Bug Fixes


- Nonce can be reused during share generation - ([deec381](https://github.com/TaceoLabs/oprf-service/commit/deec38102142f6504b485704a9fa237b78f75d80))
- Combine_proofs asks for contributing_parties - ([ea0354c](https://github.com/TaceoLabs/oprf-service/commit/ea0354c9577dcbccf4365c45ca3fdc9842bbf664))
- Their_pk is not validated during share generation - ([46372e7](https://github.com/TaceoLabs/oprf-service/commit/46372e7b85edce17f1953a5505bc8a3ba955515a))
- Lack of uniqueness check of party ID’s when computing lagrange - ([e98d9e3](https://github.com/TaceoLabs/oprf-service/commit/e98d9e35e6c06e999a7d90b4e75030c0929f8d13))

### ⚙️ Miscellaneous Tasks


- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))

