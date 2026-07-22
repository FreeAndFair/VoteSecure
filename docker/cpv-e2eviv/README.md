# Cryptographic Protocol Verification Docker Image

This folder contains everything needed to build and run the Free & Fair cryptographic protocol verification Docker image. The current image supports Tamarin-based CI/CV workflows and includes Tamarin together with the tools it relies on in practice, including Maude, Yices2, and Graphviz. It also includes ProVerif, which is currently only used by the pedagogical example.

Note that it is _far_ less efficient to run Tamarin within Docker than it is to run it natively on your hardware; Tamarin is aggressively multi-threaded and consumes large amounts of memory, so we _strongly_ recommend installing Tamarin locally instead of relying on this Docker image; the primary motivation for this image is to provide a uniform environment for running CI/CV (e.g., in GitHub actions). While the image does support both ARM64 and AMD64 platforms, it is still less efficient than running natively.

## Prerequisites

Building the image requires the following:

- make
- [Docker](https://docker.com/) or Docker-compatible tools, such as [Podman](https://podman.io/)

In order to use/run the Docker image from the [Free & Fair Dockerhub](https://hub.docker.com/repository/docker/freeandfair/cpv-e2eviv) repository, the only prerequisite is Docker or a Docker-compatible tool for the host OS.

## Building the Docker Image

The build process is simplified via a _Makefile_. Typing `make` will show the build targets, which are self-explanatory; `make image` uses `IMAGE_PLATFORM` to determine what image platforms to build. By default, `make image` builds for both `linux/amd64` and `linux/arm64`. To build only ARM64 (including on Apple Silicon Docker hosts), run:

`make IMAGE_PLATFORM=linux/arm64 image`

### Storage Requirements

A fresh multi-platform build of this image requires up to approximately 38GB of local Docker storage from a clean state. Actual usage will vary by host, Docker version, and cache state.

## Deploying the Docker Image

In order to deploy the Docker image, use `make push`. This command builds and publishes a single manifest image (`freeandfair/cpv-e2eviv:latest`) for the architectures listed in `IMAGE_PLATFORM` (default: `linux/amd64,linux/arm64`). This command requires the user to log into [DockerHub](https://hub.docker.com/) and to be a member of the [FreeAndFair](https://hub.docker.com/orgs/freeandfair) DockerHub organization with appropriate permissions to push into the [freeandfair/cpv-e2eviv](https://hub.docker.com/repository/docker/freeandfair/cpv-e2eviv) image repository. The build target performs that login automatically before pushing, but it can also be triggered manually via `make login` (to log in) and `make logout` (to log out).

## Executing the Docker Image

Two helper scripts are provided in [`scripts/`](./scripts):

- [`run-local.sh`](./scripts/run-local.sh): run a locally built image (`cpv-e2eviv`).
- [`run-remote.sh`](./scripts/run-remote.sh): pull and run the remote image (`freeandfair/cpv-e2eviv:latest`).

Both scripts map the current working directory to `/work` inside the image so files can be read and written directly from the host.

You can still run the image manually, for example:

```bash
docker run -it --rm -v "$(PWD):/work" -w "/work" freeandfair/cpv-e2eviv:latest
```

For `run-remote.sh`, Docker login is optional. If `DOCKER_READ_ONLY_TOKEN` and `DOCKER_READ_ONLY_TOKEN_USERNAME` are set, the script performs authenticated pull; otherwise it pulls anonymously.

Likewise, `make pull` is login-optional and uses the same token environment variables when provided.

## Vulnerabilities Reported by Docker Scout

Docker Scout results vary over time as upstream base images and package feeds change. For a current snapshot, run `docker scout quickview cpv-e2eviv:latest` or `docker scout quickview freeandfair/cpv-e2eviv:latest`.
