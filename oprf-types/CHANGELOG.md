# Changelog

## [Unreleased]

## [0.8.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.7.1...taceo-oprf-types-v0.8.0)

### 🐛 Bug Fixes


- Handle revert reasons during key-gen more gracefully ([#451](https://github.com/TaceoLabs/oprf-service/pull/451)) - ([d16321c](https://github.com/TaceoLabs/oprf-service/commit/d16321c98fde0aa1ed30aa380f0700baf6e91c1c))


## [0.7.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.7.0...taceo-oprf-types-v0.7.1)

### ⚙️ Miscellaneous Tasks


- Removed unused deps - ([a33e71f](https://github.com/TaceoLabs/oprf-service/commit/a33e71f2e83523fe93410eb5ddb5dafdd524ada7))


## [0.7.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.6.0...taceo-oprf-types-v0.7.0)

### 🚜 Refactor


- [**breaking**] Auth-module trait now returns the OPRF key id and removed from req ([#433](https://github.com/TaceoLabs/oprf-service/pull/433)) - ([1428e3d](https://github.com/TaceoLabs/oprf-service/commit/1428e3daf88b779838610e1e7b380b48293b006b))


## [0.6.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.5.0...taceo-oprf-types-v0.6.0)

### ⛰️ Features


- Add postgres secret-manager in service - ([3f920bd](https://github.com/TaceoLabs/oprf-service/commit/3f920bd890aea3b0307587d7851cdeaa5d82b4b7))
- Added CanonicalSerialize/Deserialize for DB storage - ([efcde52](https://github.com/TaceoLabs/oprf-service/commit/efcde524532fe4575ded5f87f3eb3777feec66fd))

### 🚜 Refactor


- [**breaking**] Reworked get_previous_share to get_share_by_epoch and updated callsite - ([8a2c100](https://github.com/TaceoLabs/oprf-service/commit/8a2c10005eaef9a37e4a0243981a77e75eda0d03))
- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### ⚙️ Miscellaneous Tasks


- Fixed stale docs - ([9807da1](https://github.com/TaceoLabs/oprf-service/commit/9807da1e14e7bfff6e9766eb75ab31151d497bdc))


## [0.5.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.4.0...taceo-oprf-types-v0.5.0)

### ⛰️ Features


- Handle revert errors from contract gracefully - ([e41fdf3](https://github.com/TaceoLabs/oprf-service/commit/e41fdf398d9a23f67c1e63fa0d4ddf7294246da7))

### 🚜 Refactor


- [**breaking**] ShareEpoch is a u32 now ([#410](https://github.com/TaceoLabs/oprf-service/pull/410)) - ([2ba29f5](https://github.com/TaceoLabs/oprf-service/commit/2ba29f5b9119e4632dfd1cb195955ace77ebf632))
- Distinguish between revert and rpc errors and always fail again - ([543a472](https://github.com/TaceoLabs/oprf-service/commit/543a4728d670b3aec36c535b2e72f78d9fe46e85))
- [**breaking**] Remove v1 concept - ([2fe5324](https://github.com/TaceoLabs/oprf-service/commit/2fe5324a2a85be97873fca0ff5a698b7d31451d4))
- Cleanup for umbrella crate - ([4f66f3a](https://github.com/TaceoLabs/oprf-service/commit/4f66f3afb0bbef6226cec4fcaece743cc1107db3))
- [**breaking**] Moved Auth trait definition to types-crate - ([d7aa19f](https://github.com/TaceoLabs/oprf-service/commit/d7aa19ffe82b4e175390c8e9afb21bd82878c206))
- [**breaking**] Update contracts to newest version - ([4065bf4](https://github.com/TaceoLabs/oprf-service/commit/4065bf4760ca17c2419603a394aaee33f7851ad2))
- Add filter for KeyGenConfirmation for party ID ([#390](https://github.com/TaceoLabs/oprf-service/pull/390)) - ([773d8b5](https://github.com/TaceoLabs/oprf-service/commit/773d8b5b5ae74333de334cadc07ad31508033928))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))

### 📚 Documentation


- Fix capitalization of TACEO:OPRF - ([181f2cd](https://github.com/TaceoLabs/oprf-service/commit/181f2cd7dc14d3d5383a7a2deaf8c57953c4302a))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.3.0...taceo-oprf-types-v0.4.0)

### ⛰️ Features


- [**breaking**] Fix number of share in OprfKeyMaterial to 2 ([#377](https://github.com/TaceoLabs/oprf-service/pull/377)) - ([d5e08b5](https://github.com/TaceoLabs/oprf-service/commit/d5e08b5fe5b7b08494f14269175627c1e9a59532))
- [**breaking**] Receive OprfPublicKey during distributed_oprf ([#366](https://github.com/TaceoLabs/oprf-service/pull/366)) - ([10eeb99](https://github.com/TaceoLabs/oprf-service/commit/10eeb999f2ab48f1ebe612b19745432c8239d73a))

### 🚜 Refactor


- [**breaking**] Update rust contract interface with new changes related to Library improvements - ([0ee6043](https://github.com/TaceoLabs/oprf-service/commit/0ee604395f48307e3bc4d8f7f899da35b64518fc))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-types-v0.2.0...taceo-oprf-types-v0.3.0)

### ⛰️ Features


- [**breaking**] Client needs to send used protocol version in header ([#361](https://github.com/TaceoLabs/oprf-service/pull/361)) - ([e43bced](https://github.com/TaceoLabs/oprf-service/commit/e43bcedd35fb37752107982cd5c873e80457c21c))
- Adds nonce to TransactionConfirmation and robustness that key-gens don't die when replicated - ([6635eb2](https://github.com/TaceoLabs/oprf-service/commit/6635eb2072be422c39bbd241c4807cb47f682813))
- [**breaking**] Nodes can register as consumers in reshare - ([c9455f9](https://github.com/TaceoLabs/oprf-service/commit/c9455f953577b25addc5157475d030419d9d66d5))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Robustness for key-gen and null responses ([#313](https://github.com/TaceoLabs/oprf-service/pull/313)) - ([7267f96](https://github.com/TaceoLabs/oprf-service/commit/7267f966049521abecc46c7a5513c1968df76958))

### 🐛 Bug Fixes


- Generate contract abi - ([3085e54](https://github.com/TaceoLabs/oprf-service/commit/3085e54a68cb662d12362141890b319641f635a0))

### 🚜 Refactor


- Reverts nonce confirmation again - ([adb4245](https://github.com/TaceoLabs/oprf-service/commit/adb4245249403254d5d3a063039ac9173eb24e7d))

### ⚙️ Miscellaneous Tasks


- Resolved error from merge - ([046330e](https://github.com/TaceoLabs/oprf-service/commit/046330ee9708cef4b67da5c3eac31c4db0a04d06))
- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))

