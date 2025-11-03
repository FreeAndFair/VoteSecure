# Project Workspace

This repository contains the Rust workspace for the VoteSecure project.

## Packages

The workspace contains the following packages:

- [cryptography](./cryptography)

  Cryptographic building blocks necessary to implement the VoteSecure protocol.

- [protocol](./protocol)

  The VoteSecure protocol implementation.

## Building

This workspace currently requires the **nightly** Rust compiler. To install and use the nightly toolchain as default, run:

```bash
rustup default nightly
```

We have also included a [rust-toolchain.toml](rust-toolchain.toml) that should run the correct toolchain for you automatically.

To build all packages in the workspace, navigate to the root of the repository and run:

```Bash
cargo build
```

To build a specific package, you can use its name. For example:

```Bash
cargo build -p cryptography
```

## Testing

To run tests for all packages (the `--test-threads` parameter is important because many of the tests, particularly those that do [Stateright](https://www.stateright.rs/) model checking, implement concurrency of their own and overall test performance suffers greatly if `cargo` also runs tests concurrently):

```Bash
cargo test -- --test-threads=1
```

To run tests for a specific package:

```Bash
cargo test -p cryptography
```

## Linting

To run clippy for all packages:

```Bash
cargo clippy
```

To run clippy for a specific package:

```Bash
cargo clippy -p cryptography
```

## Cleaning

```Bash
cargo clean
```
