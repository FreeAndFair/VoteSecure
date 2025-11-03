# Cryptol-to-Rust Compiler Docker Image

This folder contains the necessary `Dockerfile`, `Makefile` and convenience scripts to build and run the Free & Fair `cyptol-compiler` Docker image for *Rigorous Digital Engineering*.  Note that in order to build the image, access to the Galois GitLab [cryptol-compiler](https://gitlab-ext.galois.com/grindstone/cryptol-compiler) development repository is required.

The tools included in this image are `cryptol-compiler` (release 0.9.0.0) and [Z3](https://github.com/Z3Prover/z3) ([release 4.15.1](https://github.com/Z3Prover/z3/releases/tag/z3-4.15.1)) (which is needed by the compiler).  Neither [Cryptol](https://github.com/GaloisInc/cryptol) nor [Rust](https://www.rust-lang.org/) is bundled with this image.

## Prerequisites

In order to rebuild the Docker image, we must have installed the following:
- git and make
- [Docker](https://docker.com/) or Docker-compatible tools, such as [Podman](https://podman.io/), for the respective OS

On macOS, it is recommended to install these tools via [Homebrew](https://brew.sh/): `brew install git make` and use [Docker Desktop](https://www.docker.com/products/docker-desktop/) tools.

---

In order to use/run the Docker image from the [Free & Fair DockerHub](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) repository, the only prerequisites are:
- Docker or Docker-compatible tools for the respective OS

## Building the Docker Image

The build process is simplified via a *makefile*.  Simply typing `make all` will build the respective `cryptol-compiler` image locally.  The following build commands are supported:

```
make all      - clone cryptol-compiler and create Docker image
make login    - log user into DockerHub repository
make logout   - log user out of DockerHub repository
make clone    - freshly clone and prepare cryptol-compiler;
                requires access to the respecitive repository
make image    - create cryptol-compiler Docker image (in local store)
make save     - save cryptol-compiler Docker image to a tar file
make pull     - pull cryptol-compiler Docker image from DockerHub repository
make push     - push cryptol-compiler Docker image to DockerHub repository
make remove   - remove cryptol-compiler Docker image from local store
make clean    - remove all dynamically created files, incl. repository clone
make help     - display this help page (default target)
```

When creating the image locally, i.e., via `make all` or `make clone image`, the [cryptol-compiler](https://gitlab-ext.galois.com/grindstone/cryptol-compiler) development repository will be checked out locally at a suitable release tag (0.9.0.0). The local clone is used to dynamically compile the `cryptol-compiler` binary when the Docker image is created. The source repository and code is, however, not exposed in the generated `cryptol-compiler` Docker image.

We note that the build process is engineering in a way that all necessary packages and dependencies are automatically fetched from the Internet during each build, including the [Z3 SMT solver](https://github.com/Z3Prover/z3) which is required by `cryptol-compiler`. We are using GHC 9.4.8 for the build ([haskell:9.4.8](https://hub.docker.com/layers/library/haskell/9.4.8/images/sha256-71456016605eeb81199d5ad29b0ed65aa67dbed11a068aaaf9db44674a4dfcc3) public Docker image), which is the (slightly outdated) version of GHC that cryptol-compiler 0.9.0.0 recommends. We are deploying a more recent version of Z3 (4.15.1) instead of the one recommended by `cryptol-compiler` (4.8.14).

Note also that `make` only builds the image locally and does not push it to the Free & Fair DockerHub repository automatically.  The image appears in the local Docker store as `cryptol-compiler:0.9.0.0` if the build process succeeds (execute `docker images` to verify this).

## Deploying the Docker Image

In order to deploy the Docker image, use the make command `make push` after building the image.  This command requires the user to log into [DockerHub](https://hub.docker.com/) and to be a member of the [FreeAndFair](https://hub.docker.com/orgs/freeandfair) DockerHub organization with appropriate permissions to push into the [freeandfair/cryptol-compiler](https://hub.docker.com/repository/docker/freeandfair/cryptol-compiler) Docker repository.  The `push` make target performs that login automatically before pushing, but it can also be triggered manually via `make login` (to log in) and `make logout` (to log out).  The user will have to provide their DockerHub username and password at this point.

## Loading the Docker Image

The `Makefile` provides an additional command `make save` to export a previously generated local image into a `cryptol-compiler.tar` file. It can be loaded from that file via the command:

```
docker load -i cryptol-compiler.tar
```

provided the `cryptol-compiler.tar` is made available. In that case, follow the same steps for executing the Docker image locally as explained in the next section.

In practice, we expect users to fetch the image from the DockerHub [freeandfair](https://hub.docker.com/orgs/freeandfair) organization.

## Executing the Docker Image

There are two ways to run the Docker image: either locally or from the Free & Fair DockerHub remote repository (where it currently resides).  For each of these options, a script is provided inside the `scripts` folder:
- [`run-cryptol-compiler-local.sh`](./scripts/run-cryptol-compiler-local.sh)
- [`run-cryptol-compiler-remote.sh`](./scripts/run-cryptol-compiler-remote.sh)

Running the image locally (`run-cryptol-compiler-local.sh`) requires that it be either loaded or built first, as described above.  Running the image from the Free & Fair DockerHub repository (`run-cryptol-compiler-remote.sh`) does **not** require any prerequisite load or build; only the script itself, and permissions to access the [de-ple-e2eviv](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) image repository, are required.

Note that when executing `run-cryptol-compiler-remote.sh` from the command line, the user will initially have to provide access credentials for DockerHub in order to log into that repository.  Afterwards, the image should be downloaded and run automatically.  Running locally does not require any access credentials, only that the image must have previously been built or loaded.

Inside the Docker container, the following command-line tools are available: `cryptol-compiler` and `z3`.  To make it easy to use those tools from the host file system, the scripts map the current directory as `/work` into the container.  Thus it is recommended first to change to the location from which you want to run the tools on the host, then execute the scripts from there (they may be added permanently to `PATH`).  Both scripts are agnostic as to where they are executed from.

The container is run interactively by the scripts and is automatically destroyed after exiting the image, i.e., via typing `exit`.  Inside the container, all tool installations can be found under `/opt`.

## The `cryptol-compiler` Script

In addition to the above convenience scripts for running the `cryptol-compiler` Docker image, we also provide a `cryptol-compiler` script in the repository that can act as a replacement of a local `cryptol-compiler` binary, albeit forwarding any invocation of `cryptol-compiler` to the respective docker image. The script can be found under `utils/cryptol/cryptol-compiler`. Like the above `run-cryptol-compiler-remote.sh` script, it maps the current folder into the image and after command execution destroys the container. Arguments are forwarded to the `cryptol-compiler` container invocation. (It is recommended to add this to your `PATH` variable if using the Cryptol-to-Rust compiler frequently.)

<!-- Add the following section if this image might become public in the future -->
<!--
## Vulnerabilities Reported by Docker Scout

<span style="color:red">**TODO**</span>
-->

## Miscellaneous Information

The `cryptol-compiler` image is built as a _multi-platform_ for both `linux/amd64` and `linux/arm64` (`linux/arm/v8`) architectures. This means it ought run efficiently on both Intel Linux, and macOS systems with Apple chip fabric. The
- [`run-cryptol-compiler-local.sh`](./scripts/run-cryptol-compiler-local.sh)
- [`run-cryptol-compiler-remote.sh`](./scripts/run-cryptol-compiler-remote.sh)

scripts described above do not specify an architecture, meaning they will use whatever is appropriate for the current system (no [Rosetta 2](https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment) is needed on macOS.)

Any issues or bug reports should be filed in the [VoteSecure](https://github.com/FreeAndFair/VoteSecure) issue tracker.
