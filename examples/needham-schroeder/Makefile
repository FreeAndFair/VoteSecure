################################################################################
# Needham-Schroeder Pedagogical Example Makefile                               #
# @author Joe Kiniry (kiniry@freeandfair.us)                                   #
# @copyright 2025-26 Free & Fair                                               #
# @version 0.2                                                                 #
################################################################################
# Targets: make [all|help|ci|cv|bootstrap|clean]                               #
################################################################################

# ============================================================================
# Configuration
# ============================================================================

# Path to the RDE Bootstrap PLE prelude (local checkout).
RDE_BOOTSTRAP := /Users/kiniry/Sandboxes/RDE/rde-bootstrap-project/specs/ple

# Docker image containing Clafer, Lando, and Chocosolver.
DOCKER_IMAGE := freeandfair/de-ple-e2eviv:latest

# Docker run command with volume mount and entrypoint override.
DOCKER_RUN := docker run --rm --platform linux/amd64 \
	-v $(CURDIR):/work -w /work --entrypoint bash $(DOCKER_IMAGE) -c

# ============================================================================
# Tool detection
#
# Clafer and Lando are not available natively on macOS/ARM.  When a local
# installation is not found, fall back to the project Docker image.
# Chocosolver is Java/Linux-only; always use Docker on macOS.
# Syside (Sensmetry) is available natively; no Docker fallback needed.
# ============================================================================

CLAFER := $(shell command -v clafer 2>/dev/null)
LANDO  := $(shell command -v lando 2>/dev/null)
SYSIDE := $(shell command -v syside 2>/dev/null)

ifndef CLAFER
  CLAFER_CMD = $(DOCKER_RUN) \
    'clafer $(1)'
else
  CLAFER_CMD = clafer $(1)
endif

ifndef LANDO
  LANDO_CMD = $(DOCKER_RUN) \
    'lando $(1)'
else
  LANDO_CMD = lando $(1)
endif

# Chocosolver: always use Docker (Java JAR is Linux/x86-only).
CHOCOSOLVER_CMD = $(DOCKER_RUN) \
  'java -jar /work/ple/chocosolver.jar $(1)'

# ============================================================================
# Combined PLE model
# ============================================================================

PLE_MODULES := \
  ple/prelude.cfr \
  ple/architecture.cfr \
  ple/configuration.cfr \
  ple/environment.cfr \
  ple/platform.cfr \
  ple/product.cfr \
  ple/refinements.cfr \
  ple/requirements.cfr \
  ple/specifications.cfr \
  ple/system.cfr

PLE_DEPS := ple.cfr $(PLE_MODULES)

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all help ci cv clean bootstrap \
        ple typecheck validate \
        clafer-typecheck lando-typecheck sysml-typecheck

# ============================================================================
# Default and help
# ============================================================================

all: ci cv

help:
	@echo "Needham-Schroeder Pedagogical Example"
	@echo "======================================"
	@echo ""
	@echo "  make all              Run CI + CV (default)"
	@echo "  make ci               Typecheck all specifications"
	@echo "  make cv               Formal validation (Clafer inhabitance)"
	@echo ""
	@echo "  make clafer-typecheck Typecheck Clafer PLE model"
	@echo "  make lando-typecheck  Typecheck Lando domain model"
	@echo "  make sysml-typecheck  Typecheck SysMLv2 model (Sensmetry Syside)"
	@echo ""
	@echo "  make bootstrap        (Re)initialize PLE prelude from RDE Bootstrap"
	@echo "  make clean            Remove generated files"

# ============================================================================
# CI: Typecheck all specifications
# ============================================================================

ci: clafer-typecheck lando-typecheck sysml-typecheck

# Clafer typecheck: parse and resolve the combined PLE model.
clafer-typecheck: needham-schroeder.cfr
	$(call CLAFER_CMD,needham-schroeder.cfr)

# Lando typecheck: parse the domain model.
lando-typecheck: NeedhamSchroeder.lando
	$(call LANDO_CMD,convert NeedhamSchroeder.lando /dev/null --to json)

# SysMLv2 typecheck: validate the architecture model with Sensmetry Syside.
#
# `syside check` requires an active Modeler license.  Our license is only
# intermittently available, so a license failure must degrade to a warning
# and NOT fail CI/CD/CV; genuine model errors must still fail the build.
# When syside is not installed at all we likewise skip with a warning.
sysml-typecheck: NeedhamSchroeder.sysml
ifdef SYSIDE
	@output=$$(syside check --quiet NeedhamSchroeder.sysml 2>&1); status=$$?; \
	if [ $$status -eq 0 ]; then \
	  [ -n "$$output" ] && echo "$$output"; \
	  echo "[info] SysMLv2 typecheck passed."; \
	elif printf '%s' "$$output" | grep -qi 'license check failed'; then \
	  echo "WARNING: Syside Modeler license not active; skipping SysMLv2 typecheck."; \
	  printf '%s\n' "$$output" | sed 's/^/  /'; \
	else \
	  printf '%s\n' "$$output"; \
	  echo "ERROR: SysMLv2 typecheck failed." >&2; \
	  exit $$status; \
	fi
else
	@echo "WARNING: syside not found; skipping SysMLv2 typecheck."
	@echo "  Install Sensmetry Syside to enable: https://sensmetry.com/syside/"
endif

# Legacy aliases for backward compatibility.
typecheck: clafer-typecheck
validate: cv

# ============================================================================
# CV: Formal validation
# ============================================================================

cv: needham-schroeder.cfr
	$(call CHOCOSOLVER_CMD,-n 1 --maxint 100 --minint 100 \
	  --file /work/needham-schroeder.cfr)

# ============================================================================
# PLE model assembly
# ============================================================================

# Assemble the combined Clafer model from PLE modules + local model.
needham-schroeder.cfr: $(PLE_DEPS)
	cat $(PLE_MODULES) ple.cfr > needham-schroeder.cfr

# Auto-trigger bootstrap if PLE prelude is missing.
ple/prelude.cfr:
	$(MAKE) bootstrap

# ============================================================================
# Bootstrap
# ============================================================================

bootstrap:
	rm -rf ple
	cp -r $(RDE_BOOTSTRAP) .

# ============================================================================
# Clean
# ============================================================================

clean:
	rm -f needham-schroeder.cfr
