# OPRF Service

> [!WARNING]
> This repository is heavy WIP and may contain incomplete, insecure and unaudited protocols. Do not use this in production!

This is a monorepo containing:

* `circom`: A collection of Circom circuits and test vectors for them.
* `contracts`: An implementation of the required smart contracts.
* `docs`: A typst document serving as a writeup of the overall scheme.
* `noir`: A collection of Noir circuits.
* `oprf-client`: A crate implementing a client lib for the OPRF service.
* `oprf-client-example`: A crate implementing example a client.
* `oprf-core`: A crate implementing a verifiable OPRF based on the TwoHashDH OPRF construction + a threshold variant of it.
* `oprf-dev-client`: A crate implementing a dev client binary.
* `oprf-key-gen`: A crate implementing a OPRF key generation instance.
* `oprf-service`: A crate implementing a service lib for the OPRF service.
* `oprf-service-example`: A crate implementing a example OPRF node.
* `oprf-test`: A crate implementing integration tests and required mocks.
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

For development, the best way to run/test the setup is with the integration tests.

```bash
just integration-tests
```

To use the dev client, you can start the setup using the following command:

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
