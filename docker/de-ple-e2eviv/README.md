# DE/PLE Docker Image

This folder contains everything needed to build and run the Free & Fair DE/PLE Docker image for *Rigorous Digital Engineering*.  The tools included in this image are [Lando](https://github.com/GaloisInc/BESSPIN-Lando) (for Domain Engineering---DE) and [Clafer](https://www.clafer.org/p/software.html) (for Product Line Engineering---PLE).  We also include the three web-based Clafer IDEs: **ClaferMooVisualizer**, **ClaferConfigurator**, and **ClaferIDE**, exposed via ports `8092`, `8093`, and `8094` while a Docker container for the image executes.

## Prerequisites

In order to rebuild the Docker image, we must have installed the following:
- git, make, and [Maven](https://maven.apache.org/) (`mvn`)
- [OpenJDK 17](https://jdk.java.net/archive/) (to rebuild Lando from source)
- [Docker](https://docker.com/) or Docker-compatible tools, such as [Podman](https://podman.io/), for the respective OS

On MacOS, it is recommended to install these tools via [Homebrew](https://brew.sh/): `brew install git make maven podman`

---

In order to use/run the Docker image from the [Free & Fair Dockerhub](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) repository, the only prerequisites are:
- Docker or Docker-compatible tools for the respective OS

## Building the Docker Image

The build process is simplified via a *makefile*.  Simply typing `make` will build the respective `de-ple-e2eviv` image locally.  The following build commands are supported:

```
make [all]  - clone and rebuild Lando and create de-ple-e2eviv image
make login  - log user into DockerHub repository
make logout - log user out of DockerHub repository
make lando  - clone and rebuild Lando (prerequisite for building)
make image  - create de-ple-e2eviv image (in local store)
make save   - save de-ple-e2eviv image to a tar file
make pull   - pull de-ple-e2eviv image from DockerHub repository
make push   - push de-ple-e2eviv image to DockerHub repository
make remove - remove de-ple-e2eviv image from local store
make clean  - remove all dynamically created files
make help   - display this help page
```

When creating the image locally, i.e., via `make` or `make all`, the Lando tool sources will be automatically cloned from the public [BESSPIN-Land GitHub repository](https://github.com/GaloisInc/BESSPIN-Lando) and the Lando tool will be recompiled to produce a fresh JAR for deployment into the image.  The [clone-and-rebuild-lando.sh](./scripts/clone-and-rebuild-lando.sh) inside the `scripts` folder facilitates this task.  We currently use commit hash `db552ec74d4532611280693438207a72a23045b4` of the `develop` branch (the latest Galois development version on August 2, 2024) as baseline for deployment.  Since Lando does not have a periodic release cycle, we have to change this tag manually in the future by updating the `clone-and-rebuild-lando.sh` script in order to deploy a newer version of Lando via the Docker image.

We note that the build process is engineered in such a way that all Lando and Clafer tools are dynamically fetched from the Internet during each build.  The archive in [downloads/clafer-tools-0.4.5-linux-x86_64.zip](downloads/clafer-tools-0.4.5-linux-x86_64.zip) is thus not actually needed by the `Dockerfile` or installation process---it is mostly there for reference and as a fallback if online access to the [Clafer 0.4.5 distribution binary](https://gsd.uwaterloo.ca/clafer-tools-binary-distributions) fails to work at some point in the future.

Note also that `make` only builds the image locally and does not push it to the Free & Fair DockerHub repository automatically.  The image appears in the local Docker store as `de-ple-e2eviv:latest` if the build process succeeds (execute `docker images` to verify this).

## Deploying the Docker Image

In order to deploy the Docker image, use the make command `make push` after building the image.  This command requires the user to log into [DockerHub](https://hub.docker.com/) and to be a member of the [FreeAndFair](https://hub.docker.com/orgs/freeandfair) DockerHub organization with appropriate permissions to push into the [freeandfair/de-ple-e2eviv](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) image repository.  The build target performs that login automatically before pushing, but it can also be triggered manually via `make login` (to log in) and `make logout` (to log out).  The user will have to provide their DockerHub username and password at this point.

## Loading the Docker Image

Instead of using `make` to build the Docker image dynamically, it is possible to load the Docker image via the

```
docker load -i de-ple-e2eviv.tar
```

command, assuming `de-ple-e2eviv.tar` has first been downloaded from a suitable location.  In that case, follow the same steps for executing the Docker image locally as explained in the next section.

## Executing the Docker Image

There are two ways to run the Docker image: either locally or from the Free & Fair DockerHub remote repository.  For each of these options, a script is provided inside the `scripts` folder:
- [`run-de-ple-local.sh`](./scripts/run-de-ple-local.sh)
- [`run-de-ple-remote.sh`](./scripts/run-de-ple-remote.sh)

Running the image locally (`run-de-ple-local.sh`) requires that it be either loaded or built first, as described above.  Running the image from the Free & Fair DockerHub repository (`run-de-ple-remote.sh`) does **not** require any prerequisite load or build; only the script itself, and permissions to access the [de-ple-e2eviv](https://hub.docker.com/repository/docker/freeandfair/de-ple-e2eviv) image repository, are required.

Note that when executing `run-de-ple-remote.sh` from the command line, the user will initially have to provide access credentials for DockerHub in order to log into that repository.  Afterwards, the image should be downloaded and run automatically.  Running locally does not require any access credentials, only that the image must have previously been built or loaded.

Both scripts perform some additional setup to expose ports `8092`, `8093`, and `8094` in order to make the various Clafer browser-based IDEs available: **ClaferMooVisualizer**, **ClaferConfigurator**, and **ClaferIDE**.  While the container is running, the IDEs are accessed from the host via using the URLs `localhost:8092`, `localhost:8093` and `localhost:8094` in one's favorite web browser.

Inside the Docker container, the following command-line tools are available: `lando`, `clafer`, `claferIG`, and `chocosolver`.  To make it easy to use those tools from the host file system, the scripts map the current directory as `/work` into the container.  Thus it is recommended first to change to the location from which you want to run the tools on the host, then execute the scripts from there (they may be added permanently to `PATH`).  Both scripts are agnostic as to where they are executed from.

The container is run interactively by the scripts and is automatically destroyed after exiting the image, i.e., via typing `exit`.  Inside the container, all tool installations can be found under `/opt`.

## Vulnerabilities Reported by Docker Scout

Docker Scout currently flags "fixable critical or high-profile vulnerabilities" in this image. We do not intend to address these, as they do not pose any risk when using the Docker container with standard privileges to run the Clafer and Lando tooling. They are caused by:

  1. The use of Ubuntu 22.04 instead of a more recent version, which is required to provide the correct `libncurses` library for `claferIG`;
  2. The fact that Chocosolver (built from the latest revision of https://github.com/GaloisInc/chocosolver) currently requires an old version of `protobuf-java`;
  3. The fact that the Clafer Configurator (built from the latest revision of https://github.com/gsdlab/ClaferConfigurator), which is no longer actively maintained, uses an old version of `npm`.

## Miscellaneous Information

The `de-ple-e2eviv` image is built for the `linux/amd64` platform, so we do not expect any issues when running it in an Linux environment and on Intel architecture, or in the GitHub/GitLab CI.

We have not produced an `arm64` image for macOS on Apple Silicon because [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/) can execute `amd64` images via [Rosetta 2](https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment) emulation.

Should a multi-platform image be desired in the future, please contact the Free & Fair RDE team, preferably [Daniel Zimmerman](mailto:dmz@freeandfair.us?subject=RE%3A%20Help%20with%20DE%2FPLE%20docker%20image) or [Frank Zeyda](mailto:frank.zeyda@freeandfair.us?subject=RE%3A%20Help%20with%20DE%2FPLE%20docker%20image).

Lastly, any issues or bug reports should be filed in the [VoteSecure](https://github.com/FreeAndFair/VoteSecure) issue tracker.
