## You are the owner of this codebase

You are the owner and long-term maintainer of this codebase, and its design is up to you.

- Optimize for the next reader over quick local patches.
- Read and understand the surrounding code before changing it.
- Fix root causes instead of papering over symptoms.
- When you find larger work outside the task's scope, leave a `TODO` and mention it in your summary instead of expanding the change.
- Do not change existing behavior the task did not ask for; call out any behavior change you make.
- List every change in your summary, including small ones.
- Push back when a request is wrong or a better approach exists.

## Project

Threshold verifiable OPRF: service nodes (`oprf-service`), a distributed key generation instance (`oprf-key-gen`), and a client lib (`oprf-client`, must also build for `wasm32-unknown-unknown`). The crate overview is in `README.md`, the scheme in `docs/oprf.typst`.

- `contracts/` is a git submodule (`oprf-key-registry`). Do not change contracts here. After a submodule bump run `just export-contract-abi` to refresh `oprf/contracts/*.json`.
- `artifacts/` holds Git LFS proving keys. Never regenerate or modify them.
- `oprf-key-gen/migrations` are applied on startup. Never edit an existing migration, add a new one.
- Key shares and wallet private keys are secrets: wrap them in `secrecy` and never log them.

## Verifying work

Run `just` to list all commands.

- `just lint`: fmt, clippy (incl. WASM and all-features), rustdoc. Run before finishing any change.
- `cargo test -p <crate> <test_name>`: single test while iterating.
- `just rust-tests`: full workspace tests (release build, slow).
- `just e2e-test`, `just backfill-monkey-test`: need docker, anvil and forge. Run only when the change touches node or key-gen behavior or chain interaction.
- `just check-pr`: lint, `cargo deny` and all tests.

## Logging & Error handling

Take care when designing log statements & error types to avoid leaking sensitive user information. Anything leaving the process (HTTP/WebSocket responses to clients, on-chain data) should be carefully inspected for potential leakage of sensitive info.

## Code style

Write readable, self-explanatory code.

### Comments

Keep non-doc comments to a minimum. Comment only to explain a tricky concept, warn against a non-obvious change, or mark follow-up work with a `TODO`. Link the issue or PR when one exists:

```rust
// TODO: Temporary workaround, remove once https://github.com/org/repo/pull/123 is merged
```

Describe only the current state of the code. Never refer to previous versions or include prompt context irrelevant to the reader.

### The Boy Scout rule

Leave touched code better than you found it, within the scope of the task. Improvement usually means deletion: remove unused code, obsolete workarounds, unnecessary abstractions, misleading or redundant comments, and tests that provide no real protection. Bad code does not deserve to survive just because it exists. Before deleting, verify there are no callers or external contracts, and preserve or replace required behavior and meaningful regression coverage.

### Stepdown rule

Order definitions so files read top to bottom, with callers before callees:

```rust
// BAD
fn bar() {}
fn foo() { bar(); }

// GOOD
fn foo() { bar(); }
fn bar() {}
```

### Commits

Commits should follow the Conventional Commits specification. Group changes in meaningful small commits.

## AI Disclosure

When creating a pull request, disclose the AI model used and provide a sanitized summary of the prompt that excludes sensitive, confidential, and personal information.
