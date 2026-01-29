# OPRF Service

> [!WARNING]
> This repository is heavy WIP and may contain incomplete, insecure and unaudited protocols. Do not use this in production!

This is a monorepo containing:

* `circom`: A collection of Circom circuits and test vectors for them.
* `contracts`: An implementation of the required smart contracts.
* `docs`: A typst document serving as a writeup of the overall scheme.
* `noir`: A collection of Noir circuits.
* `oprf-client`: A crate implementing a client lib for the OPRF service.
* `oprf-core`: A crate implementing a verifiable OPRF based on the TwoHashDH OPRF construction + a threshold variant of it.
* `oprf-dev-client`: A crate implementing common dev client functionality.
* `oprf-key-gen`: A crate implementing a OPRF key generation instance.
* `oprf-service`: A crate implementing a service lib for the OPRF service.
* `oprf-test-utils`: A crate implementing test utils.
* `oprf-types`: A crate implementing types that are shared between client, service, and the blockchain.

## Dev Dependencies

* [just](https://github.com/casey/just?tab=readme-ov-file#installation)
* docker-compose
* anvil and forge, install with [foundryup](https://getfoundry.sh/introduction/installation/)

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

1. start `localstack` and `anvil` docker containers
2. create private keys for OPRF nodes and store them in AWS secrets manager
3. deploy the `OprfKeyRegistry` smart contract
4. register the OPRF nodes at the `OprfKeyRegistry` contract
5. start 3 OPRF nodes
6. start 3 OPRF key-gen instances

Log files for all processes can be found in the created `logs` directory.
You can kill the setup with `Ctrl+C`, which kills all processes and stops all docker containers.
You can then use the dev client to send requests using the following command:

```bash
just run-dev-client test
```

## Secret Management

The OPRF service supports two secret manager backends for storing OPRF key shares and wallet credentials.

### Postgres Secret Manager (Default)

The Postgres backend stores OPRF key shares in a PostgreSQL database while using AWS Secrets Manager only for the wallet private key. This is the recommended approach for production deployments, especially when managing many OPRF keys.

**Required environment variables:**
- `OPRF_NODE_DB_CONNECTION_STRING` – PostgreSQL connection string (e.g., `postgres://user:password@host:5432/dbname`)
- `OPRF_NODE_WALLET_PRIVATE_KEY_SECRET_ID` – Secret ID for the wallet private key (stored in AWS)
- Standard AWS credentials (for wallet key retrieval)

**Database setup:**

The Postgres secret manager automatically runs migrations on startup to create the required tables:
- `oprf_shares` – Stores OPRF key shares per epoch
- `evm_address` – Stores EVM address mappings

**Security considerations:**
- The connection string contains credentials and should be treated as a secret
- Use SSL/TLS connections in production (`?sslmode=require`)
- Ensure the database is not publicly accessible
- The wallet private key is always stored in AWS Secrets Manager for additional security

### AWS Secrets Manager

For simpler deployments with a small number of OPRF keys, you can use AWS Secrets Manager to store all secrets.

**Required environment variables:**
- `OPRF_NODE_RP_SECRET_ID_PREFIX` – Prefix for OPRF secret names
- `OPRF_NODE_WALLET_PRIVATE_KEY_SECRET_ID` – Secret ID for the wallet private key
- Standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`)
