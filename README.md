# OPRF Service

[![CI](https://github.com/TaceoLabs/oprf-service/actions/workflows/rust_test.yml/badge.svg)](https://github.com/TaceoLabs/oprf-service/actions/workflows/rust_test.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.91%2B-orange.svg)](https://www.rust-lang.org)

This is a monorepo containing:

* `contracts`: An implementation of the required smart contracts.
* `docs`: A typst document serving as a writeup of the overall scheme.
* `oprf`: A meta-crate (`taceo-oprf`) that re-exports all other crates for convenience.
* `oprf-client`: A crate implementing a client lib for the OPRF service.
* `oprf-core`: A crate implementing a verifiable OPRF based on the TwoHashDH OPRF construction + a threshold variant of it.
* `oprf-dev-client`: A crate implementing common dev client functionality.
* `oprf-key-gen`: A crate implementing a OPRF key generation instance.
* `oprf-service`: A crate implementing a service lib for the OPRF service.
* `oprf-test-utils`: A crate implementing test utils.
* `oprf-types`: A crate implementing types that are shared between client, service, and the blockchain.

## Other repositories

* [oprf-key-registry](https://github.com/TaceoLabs/oprf-key-registry): A repository containing the smart contracts in the `contracts` submodule.
* [oprf-nr](https://github.com/TaceoLabs/oprf-nr): A repository containing audited Noir circuits for proving the OPRF operations in zero-knowledge.

## Dev Dependencies

* [just](https://github.com/casey/just?tab=readme-ov-file#installation)
* docker compose (for running `anvil` and `postgres` containers)
* anvil and forge, install with [foundryup](https://getfoundry.sh/introduction/installation/)
* PostgreSQL (provided via Docker in the local setup)

## Setup

### Forge

To install the dependencies for the smart contracts run the following command:

```bash
cd contracts && forge install
```

## Test & Run

For development, we provide a `just` command that runs the full test suite for the entire workspace. This includes Circom tests, smart contract tests, and a complete end-to-end test using the example binaries.

```bash
just all-tests
```

To run the tests against a local setup, use:

```bash
just run-setup
```

This command does multiple things in order:

1. start `anvil` and `postgres` docker containers
2. deploy the `OprfKeyRegistry` smart contract
3. register the OPRF participants at the `OprfKeyRegistry` contract
4. build the workspace
5. start 3 OPRF key-gen instances
6. start 3 OPRF service nodes

Log files for all processes can be found in the created `logs` directory.
You can kill the setup with `Ctrl+C`, which kills all processes and stops all docker containers.
You can then use the dev client to send requests using the following command:

```bash
just run-dev-client test
```

## Secret Management

OPRF key shares are stored in a PostgreSQL database.

**Required environment variables:**

* `TACEO_OPRF_NODE__POSTGRES__CONNECTION_STRING` – PostgreSQL connection string (e.g., `postgres://user:password@host:5432/dbname`)
* `TACEO_OPRF_NODE__POSTGRES__SCHEMA` – Database schema to use
* `TACEO_OPRF_NODE__SERVICE__WALLET_PRIVATE_KEY` – Wallet private key for the node

The Postgres secret manager automatically runs migrations on startup to create the required tables:

* `oprf_shares` – Stores OPRF key shares per epoch
* `evm_address` – Stores EVM address mappings

**Security considerations:**

* The connection string contains credentials and should be treated as a secret
* Use SSL/TLS connections in production (`?sslmode=require`)
* Ensure the database is not publicly accessible
* The wallet private key should be provided securely (e.g., via a secrets manager in your deployment environment)

## Configuration

Both the OPRF service and key-gen are configured via environment variables using a hierarchical prefix scheme:

* **OPRF service:** `TACEO_OPRF_NODE__*` (e.g., `TACEO_OPRF_NODE__BIND_ADDR`, `TACEO_OPRF_NODE__SERVICE__ENVIRONMENT`)
* **Key generation:** `TACEO_OPRF_KEY_GEN__*` (e.g., `TACEO_OPRF_KEY_GEN__BIND_ADDR`, `TACEO_OPRF_KEY_GEN__SERVICE__WALLET_PRIVATE_KEY`)

See `run-setup.sh` for a complete example of all required environment variables.

## Architecture

For a detailed description of the OPRF scheme, see [`docs/oprf.pdf`](docs/oprf.pdf).

## License

This project is licensed under either of

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT License](http://opensource.org/licenses/MIT)

at your option.
