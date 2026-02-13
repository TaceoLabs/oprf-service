# Changelog

## [Unreleased]

## [0.4.2](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-dev-client-v0.4.1...taceo-oprf-dev-client-v0.4.2)

### Build


- *(deps)* Disable default-features for oprf-test-utils in oprf-dev-client ([#460](https://github.com/TaceoLabs/oprf-service/pull/460)) - ([7365cfa](https://github.com/TaceoLabs/oprf-service/commit/7365cfaa9d041581f41c97b92235fdd9ae422948))


## [0.4.1](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-dev-client-v0.4.0...taceo-oprf-dev-client-v0.4.1)

### ⚙️ Miscellaneous Tasks


- Updated the following local packages: taceo-oprf-types, taceo-oprf-test-utils - ([0000000](https://github.com/TaceoLabs/oprf-service/commit/0000000))


## [0.4.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-dev-client-v0.3.0...taceo-oprf-dev-client-v0.4.0)

### 🧪 Testing


- Added unit tests for delete in oprf-service - ([a4606c6](https://github.com/TaceoLabs/oprf-service/commit/a4606c62a96e5a44f3e7c3663d06f4d2529a4dde))
- Added delete test in dev-client - ([abd576f](https://github.com/TaceoLabs/oprf-service/commit/abd576f4bc20fcb49ae9449b9254006e82347a41))
- Report in stress-test which session-id failed ([#437](https://github.com/TaceoLabs/oprf-service/pull/437)) - ([b646a16](https://github.com/TaceoLabs/oprf-service/commit/b646a160e2d2f3b6f9ceb71d33b9e3f4744b80e5))


## [0.3.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-dev-client-v0.2.0...taceo-oprf-dev-client-v0.3.0)

### 🚜 Refactor


- [**breaking**] Auth-module trait now returns the OPRF key id and removed from req ([#433](https://github.com/TaceoLabs/oprf-service/pull/433)) - ([1428e3d](https://github.com/TaceoLabs/oprf-service/commit/1428e3daf88b779838610e1e7b380b48293b006b))

### 🧪 Testing


- Added stress-test for key-gen in dev-client ([#429](https://github.com/TaceoLabs/oprf-service/pull/429)) - ([e41e864](https://github.com/TaceoLabs/oprf-service/commit/e41e8641ca3197e051193a40e185575a4a9465e9))


## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-dev-client-v0.1.0...taceo-oprf-dev-client-v0.2.0)

### 🚜 Refactor


- Client now doesn't gracefully close the ws connections anymore - ([cc11858](https://github.com/TaceoLabs/oprf-service/commit/cc11858c071fc6cd2b4eda162570f888be209112))
- [**breaking**] Updated dev-client to test new resharing - ([2fed873](https://github.com/TaceoLabs/oprf-service/commit/2fed873364f5fa1d27e8336b529f893579d6053e))
- [**breaking**] Only store a single share in DB and in RAM - ([6af8d9c](https://github.com/TaceoLabs/oprf-service/commit/6af8d9c3cd34e455dda44ab42f02ce80af081a4a))

### 📚 Documentation


- Add Secret Management section to README - ([04dd050](https://github.com/TaceoLabs/oprf-service/commit/04dd050c65b69d31e61c12a3e07a18011844c076))

### 🧪 Testing


- Fixed tests again - ([a2fbc6b](https://github.com/TaceoLabs/oprf-service/commit/a2fbc6b81e191e28abbc7d128cf60c7031bcee8a))
- Fixes a bug where we got an Ok(()) value when we did not expect that - ([0908518](https://github.com/TaceoLabs/oprf-service/commit/09085184eee1cb6ea01327e2346a7cc39d97e10a))
- Restructure for the and moved testcontainer to test-utils - ([e5fb5b9](https://github.com/TaceoLabs/oprf-service/commit/e5fb5b901bb1b832878a47f010ab0abfa3486496))

### ⚙️ Miscellaneous Tasks


- Moved from confirmations to acceptance_num - ([18912df](https://github.com/TaceoLabs/oprf-service/commit/18912df54b27be6c568bf8070d94f58c85ac2657))


## [0.1.0]

### ⛰️ Features


- [**breaking**] Add support for multiple OPRF modules per OPRF service ([#401](https://github.com/TaceoLabs/oprf-service/pull/401)) - ([eea5a1e](https://github.com/TaceoLabs/oprf-service/commit/eea5a1ef330cbe34beb50d6bc16f8526bf5399f7))
- [**breaking**] Receive OprfPublicKey during distributed_oprf ([#366](https://github.com/TaceoLabs/oprf-service/pull/366)) - ([10eeb99](https://github.com/TaceoLabs/oprf-service/commit/10eeb999f2ab48f1ebe612b19745432c8239d73a))
- Replace contracts dir with submodule to oprf-key-registry repo - ([4138da2](https://github.com/TaceoLabs/oprf-service/commit/4138da2ad96597dd842ce9a826856da993892ff2))
- Add threshold 2 num_peers 5 support and test ([#298](https://github.com/TaceoLabs/oprf-service/pull/298)) - ([887b656](https://github.com/TaceoLabs/oprf-service/commit/887b6564ea4a75a6d4b66959930005aedb1ddd11))
- Add re-randomization/reshare  ([#293](https://github.com/TaceoLabs/oprf-service/pull/293)) - ([5d6aea4](https://github.com/TaceoLabs/oprf-service/commit/5d6aea452f1dac05068836f827fa5bb0803b3cb5))
- [**breaking**] Split into oprf-key-gen and oprf-service ([#291](https://github.com/TaceoLabs/oprf-service/pull/291)) - ([294b8bc](https://github.com/TaceoLabs/oprf-service/commit/294b8bc94ae59135fed205957086adce4e99d4e1))
- Remove world oprf dev client (moved to world-id-protocol) - ([a9c60d2](https://github.com/TaceoLabs/oprf-service/commit/a9c60d2e27d030c639714679e95a6ff70da1afbc))
- Use http instead of ws rpc url in dev client - ([68fb4be](https://github.com/TaceoLabs/oprf-service/commit/68fb4be880309353cc7b204e314ace33dc88f7c5))
- Now can provide connector to client - ([5ca8c55](https://github.com/TaceoLabs/oprf-service/commit/5ca8c557a20f48a35672dde47ed891aaa707fb56))
- Added ws functionality - ([15b1670](https://github.com/TaceoLabs/oprf-service/commit/15b1670564c9309e1bd8e82ab553099a204faeb4))
- [**breaking**] Add new-type just for blinding factor to ensure CryptoRng was used to generate ([#281](https://github.com/TaceoLabs/oprf-service/pull/281)) - ([e1ec8b5](https://github.com/TaceoLabs/oprf-service/commit/e1ec8b54adbb6628286049019132abfab5a42c90))
- Add back updated README ([#282](https://github.com/TaceoLabs/oprf-service/pull/282)) - ([f5bf211](https://github.com/TaceoLabs/oprf-service/commit/f5bf2115ab962d0725307fab8ad2fae16da65b27))
- Update domain separator for query proof ([#233](https://github.com/TaceoLabs/oprf-service/pull/233)) - ([e309d25](https://github.com/TaceoLabs/oprf-service/commit/e309d25176bcc613a54dc1915c4dc2bd337c72e1))
- Generated new zkeys + upadted kats - ([a10f5b7](https://github.com/TaceoLabs/oprf-service/commit/a10f5b7111c4155cd65634d0e9747aa9fa65e379))
- Add possibility to delete rp material - ([ff0b7d1](https://github.com/TaceoLabs/oprf-service/commit/ff0b7d1191f6bbcedd5f5fb7384cdce6be5f8d32))
- Use world-id-primitives and indexer docker image ([#160](https://github.com/TaceoLabs/oprf-service/pull/160)) - ([c8a25df](https://github.com/TaceoLabs/oprf-service/commit/c8a25dfd25a6ae804cd4d5786e19a20dce077390))
- Use ephemeral keys for key generation - ([90ce604](https://github.com/TaceoLabs/oprf-service/commit/90ce60408934554b27343a3ed474e2f8f3d466db))
- Unify zk implementations in new oprf-zk crate ([#136](https://github.com/TaceoLabs/oprf-service/pull/136)) - ([a6d1b52](https://github.com/TaceoLabs/oprf-service/commit/a6d1b52c4e61bb3fa245fa290f65ccc2761b664e))
- Update world_id_protocol_mock and always set tree depth to 30 ([#138](https://github.com/TaceoLabs/oprf-service/pull/138)) - ([82fe86c](https://github.com/TaceoLabs/oprf-service/commit/82fe86c796c3b447d4fba9a69c40bc3e00f984d0))
- Add onchain verification functionality ([#135](https://github.com/TaceoLabs/oprf-service/pull/135)) - ([512fba4](https://github.com/TaceoLabs/oprf-service/commit/512fba45f492da73918d42703fdb96f00b890191))
- Load existing rp secrets from AWS secretsmanager - ([beccee3](https://github.com/TaceoLabs/oprf-service/commit/beccee3bdbe5c037b20e696fa205d54b3390b817))
- Improve dev client - ([45a9121](https://github.com/TaceoLabs/oprf-service/commit/45a91215c2308258f36972c144d6c4c107f5bbdf))
- Drop openssl dependency ([#113](https://github.com/TaceoLabs/oprf-service/pull/113)) - ([a7894c5](https://github.com/TaceoLabs/oprf-service/commit/a7894c57f6d034f8204b4607b5e947aa8b11dcdc))
- Rewrite to use smart-contract key gen (still mock) ([#100](https://github.com/TaceoLabs/oprf-service/pull/100)) - ([8a4cb8c](https://github.com/TaceoLabs/oprf-service/commit/8a4cb8c5a5e79fd6ca4e929d8a2974e6bcffb45f))
- Add oprf-dev-client - ([62e07bd](https://github.com/TaceoLabs/oprf-service/commit/62e07bdd374c2bd0ac4dd459174958fd5e5dccbb))

### 🐛 Bug Fixes


- *(test)* Wait 5 seconds to resolve race condition from world indexer ([#223](https://github.com/TaceoLabs/oprf-service/pull/223)) - ([798b0c5](https://github.com/TaceoLabs/oprf-service/commit/798b0c589622eeacf30f9fae059643b1d7ab7ddc))
- Dont include finish request generation in init throughput measurement ([#393](https://github.com/TaceoLabs/oprf-service/pull/393)) - ([401b19b](https://github.com/TaceoLabs/oprf-service/commit/401b19bf8f8182cd1d80fd800d597baea05899cb))
- Make docker-compose.yml work for mac ([#202](https://github.com/TaceoLabs/oprf-service/pull/202)) - ([48d950c](https://github.com/TaceoLabs/oprf-service/commit/48d950c34cda35319d756f966070afc9bad3be18))
- Update address parsing for local setup ([#159](https://github.com/TaceoLabs/oprf-service/pull/159)) - ([6b31eb7](https://github.com/TaceoLabs/oprf-service/commit/6b31eb776e67aea467621ab7e112d23cb3b5a082))
- Various fixes for on-chain deployment - ([20a2a95](https://github.com/TaceoLabs/oprf-service/commit/20a2a955cdc4d75f40d6f75d7ef6b8ee30d24f94))
- Poll indexer for inclusion proof in dev-client, it can take some time before account exists ([#147](https://github.com/TaceoLabs/oprf-service/pull/147)) - ([ef93711](https://github.com/TaceoLabs/oprf-service/commit/ef93711a33b285fce746c4b25e545b34843f80e2))
- Change timestamp from millis to secs - ([8dac3b8](https://github.com/TaceoLabs/oprf-service/commit/8dac3b807d9c1f843142ffe52dd3b5edc42962c9))
- Logging fix and remove some broken docs ([#98](https://github.com/TaceoLabs/oprf-service/pull/98)) - ([42f4c7f](https://github.com/TaceoLabs/oprf-service/commit/42f4c7f9c5ceaa262648929f48f2de17a22cda6c))

### 🚜 Refactor


- [**breaking**] ShareEpoch is a u32 now ([#410](https://github.com/TaceoLabs/oprf-service/pull/410)) - ([2ba29f5](https://github.com/TaceoLabs/oprf-service/commit/2ba29f5b9119e4632dfd1cb195955ace77ebf632))
- Added example oprf-service/dev-client - ([0398347](https://github.com/TaceoLabs/oprf-service/commit/0398347e0bfefaf67d4d88d169cfe094a78545a8))
- [**breaking**] Remove v1 concept - ([2fe5324](https://github.com/TaceoLabs/oprf-service/commit/2fe5324a2a85be97873fca0ff5a698b7d31451d4))
- [**breaking**] Split oprf-test into oprf-test-utils and oprf-test, split oprf-dev-client into oprf-dev-client lib and example bin ([#370](https://github.com/TaceoLabs/oprf-service/pull/370)) - ([5ca9019](https://github.com/TaceoLabs/oprf-service/commit/5ca90197fba1f19d0e74f595d383695d111dcbfb))
- Remarks dk/fg (first patch) - ([70d4839](https://github.com/TaceoLabs/oprf-service/commit/70d4839306c625567cc8923857c0cbec62049170))
- [**breaking**] Removed unecessary challenge req/resp structs - ([a8c6165](https://github.com/TaceoLabs/oprf-service/commit/a8c61656824085c7ffd5eed92cd374cfdaa2c609))
- [**breaking**] Oprf-service and client generalization ([#275](https://github.com/TaceoLabs/oprf-service/pull/275)) - ([73d6709](https://github.com/TaceoLabs/oprf-service/commit/73d6709b16eb24e2254df1ac316cbe1fff3b53fb))
- Removed oprf-zk crate and use groth16-material crate instead ([#235](https://github.com/TaceoLabs/oprf-service/pull/235)) - ([eb182d0](https://github.com/TaceoLabs/oprf-service/commit/eb182d0c03518bd301dea75f638963c8983b4c77))
- [**breaking**] Split oprf-types into 2 crates 1 for general oprf types and 1 for world specific types ([#169](https://github.com/TaceoLabs/oprf-service/pull/169)) - ([69f3c0d](https://github.com/TaceoLabs/oprf-service/commit/69f3c0d8751286bcca4e08cab1febb9d7496b48a))
- Rename KeyGen contract to RpRegistry ([#144](https://github.com/TaceoLabs/oprf-service/pull/144)) - ([3d3843d](https://github.com/TaceoLabs/oprf-service/commit/3d3843d148fa0f91a03fa7fc8093e927a04bff83))
- First real version of the KeyGen smart contract - ([6d72479](https://github.com/TaceoLabs/oprf-service/commit/6d724792274c325c6cfc8ce9fca9c29761331ec8))

### 📚 Documentation


- Added docs for client - ([a5782a2](https://github.com/TaceoLabs/oprf-service/commit/a5782a2ffed3609531f0a3a6251fc31d61cdab13))

### 🧪 Testing


- [**breaking**] Added test setup and integration test-suites for key-gen + service - ([57b10fa](https://github.com/TaceoLabs/oprf-service/commit/57b10fa47eb3dc81cff6b96988fbbe7e99275080))

### ⚙️ Miscellaneous Tasks


- Prepare crates for publishing - ([3b5a066](https://github.com/TaceoLabs/oprf-service/commit/3b5a066f09041e89a3b8371cddde4c50fad7407a))
- Updated readme - ([279f20e](https://github.com/TaceoLabs/oprf-service/commit/279f20ef722aecebc8a2a9f58a9688c4d2f88c80))
- Rename submodule to contracts - ([e58e29a](https://github.com/TaceoLabs/oprf-service/commit/e58e29a3eba67e68ab69de2093c689060a7bb881))
- Fix log targets - ([fa9d6d8](https://github.com/TaceoLabs/oprf-service/commit/fa9d6d8a545e8151ad679ba956cd756beb20e6af))
- [**breaking**] Prepare for publish ([#318](https://github.com/TaceoLabs/oprf-service/pull/318)) - ([e09a6b1](https://github.com/TaceoLabs/oprf-service/commit/e09a6b1f42749c879a9546d07f15b5df93cdd354))
- Fix path in justfile and dev-client ([#213](https://github.com/TaceoLabs/oprf-service/pull/213)) - ([82772aa](https://github.com/TaceoLabs/oprf-service/commit/82772aa1e5cfb1bbfc4b9664258e4b548564d269))
- Cleanup ([#155](https://github.com/TaceoLabs/oprf-service/pull/155)) - ([110ff28](https://github.com/TaceoLabs/oprf-service/commit/110ff2836623dea1d4a9191f7d116ec25c89291f))

### Build


- Prepare publish by removing git deps ([#260](https://github.com/TaceoLabs/oprf-service/pull/260)) - ([473667c](https://github.com/TaceoLabs/oprf-service/commit/473667cb16b8d8d6a76b79c4bfdf0b07315db07f))

