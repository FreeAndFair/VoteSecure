################################################################################
# Dockerfile for generating the isabelle-ci docker image used by the GitHub CI #
################################################################################
# File: docker/isabelle-ci/Dockerfile
# Author: Frank Zeyda, Daniel M. Zimmerman
# Created: 2026-03-02
# Modified: 2026-07-28

# Note that building this image requires a higher Memory Limit, e.g.,
# of 16 GB. This can be adjusted under Resources in Docker Desktop.
FROM ubuntu:26.04

# Multi-architecture build argument
ARG TARGETARCH

# Specify the Isabelle version to install
ARG ISABELLE_VERSION="Isabelle2025-2"
ARG ISABELLE_TARBALL_AMD64="${ISABELLE_VERSION}_linux.tar.gz"
ARG ISABELLE_TARBALL_ARM64="${ISABELLE_VERSION}_linux_arm.tar.gz"

# Used to verify Isabelle download (adjust when version changes)
ARG ISABELLE_SHA256_AMD64=\
"a20a507bc7c1270d8be96a9f3fbec06345387789d2dc2c4d3df6260d47bfb33c"
ARG ISABELLE_SHA256_ARM64=\
"650a9669b4a087675afb34294d82ded2f0704d47d580dd9ed45cddc9f1764bdd"

# Install packages in noninteractive mode
ENV DEBIAN_FRONTEND=noninteractive

# Install packages for dependencies
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      locales \
      texlive-full \
      latexmk && \
    apt-get clean

# Set up environment for Unicode
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL="en_US.UTF-8"

# Isabelle distribution sources, tried in order until one downloads and
# matches the expected SHA256 (the main site occasionally serves partial
# or corrupted downloads under load)
ARG ISABELLE_DIST_URLS="\
https://isabelle.in.tum.de/dist \
https://www.cl.cam.ac.uk/research/hvg/Isabelle/dist \
https://mirror.clarkson.edu/isabelle/dist"

# Install the Isabelle tool
RUN cd /opt && \
  case "${TARGETARCH}" in \
      "amd64") ISABELLE_TARBALL=${ISABELLE_TARBALL_AMD64}; ISABELLE_SHA256=${ISABELLE_SHA256_AMD64} ;; \
      "arm64") ISABELLE_TARBALL=${ISABELLE_TARBALL_ARM64}; ISABELLE_SHA256=${ISABELLE_SHA256_ARM64} ;; \
      *) echo "Unsupported arch: ${TARGETARCH}" && exit 1 ;; \
      esac && \
  for DIST_URL in ${ISABELLE_DIST_URLS}; do \
    echo "Fetching ${ISABELLE_TARBALL} from ${DIST_URL} ..." && \
    rm -f ${ISABELLE_TARBALL} && \
    if curl -fL --retry 3 -o ${ISABELLE_TARBALL} "${DIST_URL}/${ISABELLE_TARBALL}" && \
       echo "${ISABELLE_SHA256} ${ISABELLE_TARBALL}" | sha256sum --check; \
    then \
      break; \
    else \
      echo "Download from ${DIST_URL} failed or checksum mismatch; trying next source."; \
    fi; \
  done && \
  tar xzvf ${ISABELLE_TARBALL} && \
  rm ${ISABELLE_TARBALL} && \
  ln -s ${ISABELLE_VERSION} Isabelle

# Set Isabelle installation directory
ENV ISABELLE_HOME="/opt/Isabelle"

# Add binaries to PATH
ENV PATH="/opt/Isabelle/bin:$PATH"

# Create local user to run container as by default
# Note that 1000 is already taken for the ubuntu user.
RUN groupadd -g 1001 isabelle
RUN useradd -m -s /bin/bash -u 1001 -g isabelle isabelle
RUN echo isabelle:isabelle | chpasswd
# RUN chown -R isabelle:isabelle /opt/Isabelle${ISABELLE_VERSION}

# Set Isabelle user directory (seems to be ignored though)
ENV ISABELLE_HOME_USER="/home/isabelle/.isabelle/${ISABELLE_VERSION}"

# From now on, operate as the 'isabelle' user
USER isabelle
WORKDIR /home/isabelle

# Quick sanity check that Isabelle is up
RUN isabelle version

# Prebuild HOL and HOL-Algebra heaps
RUN isabelle build -v -b HOL
RUN isabelle build -v -b HOL-Algebra
