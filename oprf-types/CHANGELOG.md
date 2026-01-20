# Changelog

## [Unreleased]

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

