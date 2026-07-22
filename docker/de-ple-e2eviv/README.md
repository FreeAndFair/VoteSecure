# DE/PLE Docker Image

This folder contains everything needed to build and run the Free & Fair DE/PLE Docker image for *Rigorous Digital Engineering*. The image includes [Lando](https://github.com/GaloisInc/BESSPIN-Lando) (for Domain Engineering---DE), [Clafer](https://www.clafer.org/p/software.html) (for Product Line Engineering---PLE), `claferIG`, Chocosolver, PlantUML, and the three web-based Clafer IDEs (**ClaferMooVisualizer**, **ClaferConfigurator**, and **ClaferIDE**, which are exposed by the Docker images via ports `8092`, `8093`, and `8094` respectively).

## Prerequisites

In order to rebuild the Docker image, you need the following:

- git and make
- [Docker](https://docker.com/) or Docker-compatible tools, such as [Podman](https://podman.io/), for the respective OS

On macOS, it is recommended to install these tools via [Homebrew](https://brew.sh/): `brew install git make`

---

In order to use/run the Docker image from the [Free & Fair DockerHub](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) repository, the only prerequisite is Docker or a Docker-compatible tool for the host OS.

## Building the Docker Image

The build process is simplified via a *Makefile*. Simply typing `make` displays the help text for the image build; to build the image locally, use `make image`. The following build commands are supported:

```text
make [all]  - display help
make login  - log user into DockerHub repository
make logout - log user out of DockerHub repository
make image  - create de-ple-e2eviv image (in local store)
make save   - save de-ple-e2eviv image to a tar file
make pull   - pull de-ple-e2eviv image from DockerHub repository
make push   - push de-ple-e2eviv image to DockerHub repository
make remove - remove de-ple-e2eviv image from local store
make clean  - remove all dynamically created files
make help   - display this help page
```

The image build honors `IMAGE_PLATFORM`, which defaults to `linux/amd64,linux/arm64`. To build only one platform, for example on Apple Silicon or when conserving build time, run:

```bash
make IMAGE_PLATFORM=linux/arm64 image
```

Note also that `make` only builds the image locally and does not push it to the Free & Fair DockerHub repository automatically.  The image appears in the local Docker store as `de-ple-e2eviv:latest` if the build process succeeds (execute `docker images` to verify this).

### Storage Requirements

A fresh multi-platform build of this image requires up to approximately 44GB of local Docker storage from a clean state. Actual usage will vary by host, Docker version, and cache state.

## Deploying the Docker Image

In order to deploy the Docker image, use the make command `make push` after building the image.  This command requires the user to log into [DockerHub](https://hub.docker.com/) and to be a member of the [FreeAndFair](https://hub.docker.com/orgs/freeandfair) DockerHub organization with appropriate permissions to push into the [freeandfair/de-ple-e2eviv](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) image repository.  The build target performs that login automatically before pushing, but it can also be triggered manually via `make login` (to log in) and `make logout` (to log out).  The user will have to provide their DockerHub username and password at this point.

## Loading the Docker Image

Instead of using `make` to build the Docker image dynamically, it is possible to load the Docker image via the

```sh
docker load -i de-ple-e2eviv.tar
```

command, assuming `de-ple-e2eviv.tar` has first been downloaded from a suitable location.  In that case, follow the same steps for executing the Docker image locally as explained in the next section.

## Executing the Docker Image

There are two ways to run the Docker image: either locally or from the Free & Fair DockerHub remote repository. Run scripts are provided in the `scripts` folder:

- [`run-local.sh`](./scripts/run-local.sh)
- [`run-remote.sh`](./scripts/run-remote.sh)

Running the image locally (`run-local.sh`) requires that it be either loaded or built first, as described above. Running the image from the Free & Fair DockerHub repository (`run-remote.sh`) does **not** require any prerequisite load or build; only the script itself, and permissions to access the [de-ple-e2eviv](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) image repository, are required.

For `run-remote.sh`, Docker login is optional. If `DOCKER_READ_ONLY_TOKEN` and `DOCKER_READ_ONLY_TOKEN_USERNAME` are set, the script performs an authenticated pull; otherwise it pulls anonymously. Likewise, `make pull` is login-optional and uses the same token environment variables when provided. Running locally does not require any access credentials, only that the image must have previously been built or loaded.

Both scripts run on the host's native platform by default. To override platform selection explicitly, set `DE_PLE_PLATFORM` (for example, `DE_PLE_PLATFORM=linux/amd64` or `DE_PLE_PLATFORM=linux/arm64`) before running the script.

Inside the Docker container, the following command-line tools are available: `lando`, `clafer`, `claferIG`, `chocosolver`, and `plantuml`. To make it easy to use those tools from the host file system, the scripts map the current directory as `/work` into the container. Thus it is recommended first to change to the location from which you want to run the tools on the host, then execute the scripts from there (they may be added permanently to `PATH`). Both scripts are agnostic as to where they are executed from. For `chocosolver`, the Java heap size can be overridden by setting the `CHOCOSOLVER_HEAP_SIZE` environment variable.

The container is run interactively by the scripts and is automatically destroyed after exiting the image, i.e., via typing `exit`.  Inside the container, all tool installations can be found under `/opt`.

## Vulnerabilities Reported by Docker Scout

Docker Scout may flag critical or high-profile vulnerabilities in this image, as some of the DE/PLE tools require outdated versions of certain dependencies. We currently prioritize reproducibility and tool compatibility for DE/PLE workflows; vulnerability remediation is tracked separately and should be evaluated against concrete runtime risk in this non-privileged tool container use case.

Docker Scout results vary over time as upstream base images and package feeds change. For a current snapshot, run `docker scout quickview de-ple-e2eviv:latest` or `docker scout quickview freeandfair/de-ple-e2eviv:latest`.

## Miscellaneous Information

The full `de-ple-e2eviv` image builds for both `linux/amd64` and `linux/arm64`, and in CI/local use you should prefer native execution by default and override platform only when explicitly needed.

Known limitation (as of April 2026): with the `linux/arm64` image, `claferIG`/Alloy instance generation is currently unreliable due to a MiniSatProver runtime assertion failure in the native JNI solver path. The image still includes `claferIG`, but for reliable instance generation on ARM use `chocosolver` instead (already the default in the feature-model workflow). If you specifically need `claferIG`/Alloy behavior, run the image with `DE_PLE_PLATFORM=linux/amd64`.

Any issues or bug reports should be filed in the project issue tracker.
