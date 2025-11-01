# VoteSecure Core Cryptographic Library Development

### ⚠️ Requirements

This crate requires the **nightly** Rust compiler. To install and use the nightly toolchain, run:
```bash
rustup default nightly
```

### Setting up pre-commit hooks

To install (pre-commit hooks)[https://github.com/FreeAndFair/MobileVotingCoreCryptography/blob/main/docs/team.md#pre-commit-hooks] (requires python):

```bash
pip install pre-commit
pre-commit install
```

To manually run pre-commit hooks:

```bash
pre-commit run --all-files
```

### Building Documentation

**1. Generate the Documentation**

Run the following Cargo command from the root of the project:

```bash
cargo doc --no-deps --document-private-items
```

**2. Open in Your Browser**

Once the command finishes, the main documentation page will be located at:

```code
target/doc/crypto/index.html
```

Open this file in your web browser to view the docs.

You can also run this command, which will automatically build the docs and open the main page in your default browser:

```bash
cargo doc --no-deps --document-private-items --open
```

### Running Tests

To run tests, use the following command:

```bash
cargo test
```

To run only doctests:

```bash
cargo test --doc
```

To run all tests _except_ doctests:

```bash
cargo test --lib --bins --tests
```

### Lints and static analysis

#### Running [clippy](https://doc.rust-lang.org/clippy/)

```bash
cargo clippy
```

Clippy lint configuration is specified in `Cargo.toml` (TODO: move to workspace)

#### Code coverage

Install [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov):

```bash
cargo install cargo-llvm-cov
```

Run the analysis:

```bash
cargo llvm-cov
```

To run and open an html report:

```bash
cargo llvm-cov
cargo llvm-cov report --html --open
```

To enable branch analysis

```bash
cargo llvm-cov --branch
```

#### Supply chain analysis

#### Cargo deny

Install [cargo deny](https://embarkstudios.github.io/cargo-deny/index.html):

```bash
cargo install cargo-deny
```

Run the analysis:

```bash
cargo deny check
```

#### Cargo vet

Install [cargo vet](https://mozilla.github.io/cargo-vet/index.html):

```bash
cargo install --locked cargo-vet
```

Run the analysis:

```bash
cargo vet
```

#### Cargo miri

You will need to install [miri](https://github.com/rust-lang/miri?tab=readme-ov-file#using-miri) and [cargo-nexttest](https://nexte.st/docs/installation/pre-built-binaries/). Then run

```bash
cargo miri nextest run -jN
```

Setting N to available cores (for example `cargo miri nextest run -j12` for a 12 core machine).

#### Cargo fuzz

You will need to install [cargo-fuzz](https://rust-fuzz.github.io/book/introduction.html). Then run

```bash
cargo fuzz list
```

to list the fuzz targets, and

```bash
cargo fuzz run <target>
```

to run a fuzz target.

#### Custom warnings

To display custom warnings when running `cargo check/build/test/run`,
pass in ```--features=custom-warnings```:

```bash
cargo build --features=custom-warnings
```

Custom warnings are implemented in ```workspace/macros/custom_warning_macro```.
