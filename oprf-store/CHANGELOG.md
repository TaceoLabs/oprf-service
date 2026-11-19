# Changelog

## [Unreleased]

## [0.2.0](https://github.com/TaceoLabs/oprf-service/compare/taceo-oprf-store-v0.1.0...taceo-oprf-store-v0.2.0)

### ⛰️ Features


- *(key-gen)* [**breaking**] Upgrade direct rows to the storage envelope on startup - ([e5965e0](https://github.com/TaceoLabs/oprf-service/commit/e5965e02c31e66f259c9a87d17c03df4397fc06f))
- *(key-gen)* [**breaking**] Read and write shares through the storage envelope - ([d4db924](https://github.com/TaceoLabs/oprf-service/commit/d4db92411c100a853dc38b6aeb831d10787fa95b))
- *(key-gen)* Add storage format configuration - ([4cbf809](https://github.com/TaceoLabs/oprf-service/commit/4cbf80906a0bf739b17a215207eccc9db06c1369))
- *(service)* [**breaking**] Read shares through the storage envelope - ([1c8b6db](https://github.com/TaceoLabs/oprf-service/commit/1c8b6dba41280463ed994f5862f25bc60fe348a8))
- *(store)* Add data key table access - ([65af74d](https://github.com/TaceoLabs/oprf-service/commit/65af74dd601f8d261004c0d13feb3622775cdc0d))
- *(store)* Add storage format policy - ([30ee0f2](https://github.com/TaceoLabs/oprf-service/commit/30ee0f208d31cbbb65aa8a2d3e3c023257925d0b))
- *(store)* Add KMS data key wrapper - ([98a34bb](https://github.com/TaceoLabs/oprf-service/commit/98a34bb6c215007b4a32b4b718eeff814362f206))
- *(store)* Add AES-256-GCM data key cipher - ([8fba817](https://github.com/TaceoLabs/oprf-service/commit/8fba817f719ab3bbb2741be59a8c24a0e18cb69a))
- *(store)* Add storage format and row AAD - ([7267ce7](https://github.com/TaceoLabs/oprf-service/commit/7267ce7436d611fd8617c32b3893b9a224ad5efb))

### 🐛 Bug Fixes


- *(store)* Check the key reported by KMS against the configured ARN - ([5ada2eb](https://github.com/TaceoLabs/oprf-service/commit/5ada2eb0826223c593f73ddb6f94840451e4ab76))
- *(store)* Zeroize sealed bytes - ([b0af7e8](https://github.com/TaceoLabs/oprf-service/commit/b0af7e86087f8c47b32c49430dfff0d6e0427303))

### 🚜 Refactor


- *(store)* Remove lock for initial key creation - ([97243f9](https://github.com/TaceoLabs/oprf-service/commit/97243f9e8b9ed8b6f6a325f32d7002f8e840c9ca))
- *(store)* Let data key functions take any executor - ([1172852](https://github.com/TaceoLabs/oprf-service/commit/1172852b411d8d945536ae64e7231639f35a5131))
- [**breaking**] Parse storage configs and prepare key-gen storage at init - ([e543b1b](https://github.com/TaceoLabs/oprf-service/commit/e543b1b207283d4ca56019eda0b37d621f80ae51))
- [**breaking**] Drop chain id and registry from the storage AAD - ([ed3627e](https://github.com/TaceoLabs/oprf-service/commit/ed3627e60a6f3e952997aba812c2e6fce69d0e8f))

### 🏗️ Build


- Upgrade aes-gcm to 0.11 - ([6fc82d2](https://github.com/TaceoLabs/oprf-service/commit/6fc82d2c65b69f65fa0689c173dd804dbcc22662))

### 🧪 Testing


- *(store)* Remove redundant tests - ([909b444](https://github.com/TaceoLabs/oprf-service/commit/909b4444f9fcee06973b7dbeb65470e7d94f4600))
- *(store)* Pin the stored format with a known-answer test - ([0ed4aa8](https://github.com/TaceoLabs/oprf-service/commit/0ed4aa80c1d6a2676d32995549cd3c19374ac69b))

