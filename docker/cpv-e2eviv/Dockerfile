#####################################################################
# Dockerfile for the Free&Fair CPV DE/PLE Docker image (cpv-e2eviv) #
#                                                                   #
# Author: Daniel M. Zimmerman                                       #
# Created: 2025-06-06                                               #
# Modified: 2026-07-24                                              #
#####################################################################

# Builder stage: use official Homebrew Docker image to build cross-platform
# Tamarin and dependencies.
FROM homebrew/brew AS tamarin-builder

RUN brew update

# Add tamarin-prover tap and install Tamarin, Maude, and Yices.
# Graphviz is pulled in as a Tamarin dependency.
RUN brew tap tamarin-prover/tap && \
    brew trust tamarin-prover/tap && \
    brew install tamarin-prover/tap/tamarin-prover && \
    brew install yices2

# Builder state: use OPAM to build and install ProVerif and
# dependencies.
FROM ubuntu:24.04 AS proverif-builder

RUN apt-get clean && \
    apt-get update && \
    apt-get install -y software-properties-common
RUN add-apt-repository ppa:avsm/ppa && \
    apt-get install -y ocaml opam libexpat1-dev libgtk2.0-dev pkg-config && \
    apt-get clean

RUN opam init --disable-sandboxing --shell-setup --yes
RUN opam update
RUN opam install proverif --yes

# Builder stage: use Ubuntu 26.04 to build tamarin-rs.
FROM rust:latest AS tamarin-rs-builder

# Install runtime dependencies
RUN apt-get clean && \
    apt-get update && \
    apt-get install -y git && \
    apt-get clean

ARG TAMARIN_RS_REPO=https://github.com/kmilner/tamarin-rs.git
ARG TAMARIN_RS_REF=main

RUN git clone --filter=blob:none "$TAMARIN_RS_REPO" && \
    cd tamarin-rs && \
    git checkout "$TAMARIN_RS_REF"

RUN cd tamarin-rs && \
    ./setup.sh && \
    cargo build --release

# Runtime image based on Ubuntu 26.04
FROM ubuntu:26.04 AS runtime

ENV HOMEBREW_PREFIX=/home/linuxbrew/.linuxbrew
ENV PATH=${HOMEBREW_PREFIX}/bin:${HOMEBREW_PREFIX}/sbin:/usr/local/bin:$PATH
ENV LD_LIBRARY_PATH=${HOMEBREW_PREFIX}/lib
ENV MAUDE_LIB=${HOMEBREW_PREFIX}/opt/maude/share

# Copy entire Homebrew installation from builder
COPY --from=tamarin-builder /home/linuxbrew/.linuxbrew /home/linuxbrew/.linuxbrew

# Copy tamarin-rs binary from builder
COPY --from=tamarin-rs-builder /tamarin-rs/target/release/tamarin-rs /usr/local/bin

# Copy ProVerif installation from builder
COPY --from=proverif-builder /root/.opam/default/bin/proverif /usr/local/bin/proverif

RUN apt-get clean && \
    apt-get update && \
    apt-get install -y locales libexpat1-dev libgtk2.0-dev pkg-config && \
    apt-get clean

# Set up environment for Unicode
RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
    locale-gen en_US.UTF-8
ENV LC_ALL="en_US.UTF-8"

# Create and run as non-root user
RUN groupadd -g 1001 cpv && \
    useradd -m -u 1001 -g 1001 cpv
USER cpv

# Set the default working directory
WORKDIR /home/cpv

# Passed to and executed by startup.sh
CMD ["/bin/bash"]
