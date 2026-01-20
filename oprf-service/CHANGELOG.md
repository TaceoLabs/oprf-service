# Changelog

## [Unreleased]

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

