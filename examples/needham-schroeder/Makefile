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

# Docker images.
#  - PLE image: Clafer, Lando, Chocosolver.
#  - CPV image: Tamarin.  (It bundles NEITHER ProVerif NOR Cryptol.)
PLE_IMAGE := freeandfair/de-ple-e2eviv:latest
CPV_IMAGE := freeandfair/cpv-e2eviv:latest

# Docker run helpers.  PLE tools are invoked through bash (-c) so we can pass a
# single command string; CPV tools (Tamarin) are invoked directly.
PLE_DOCKER_RUN := docker run --rm --platform linux/amd64 \
	-v $(CURDIR):/work -w /work --entrypoint bash $(PLE_IMAGE) -c
CPV_DOCKER := docker run --rm --platform linux/amd64 \
	-v $(CURDIR):/work -w /work $(CPV_IMAGE)

# ============================================================================
# Tool detection
#
# Each container-backed tool (Clafer/Lando/Chocosolver -> PLE image;
# Tamarin -> CPV image) is used natively when installed, otherwise via its
# Docker image.  Set USE_DOCKER=yes to force container execution even when a
# local tool exists (useful when a local install is broken).  Tools that no
# project image bundles -- Syside, ProVerif, and Cryptol -- degrade to a
# warning-and-skip when absent so that CI/CD/CV stays green in environments
# that lack them (see the individual targets).
# ============================================================================

CLAFER   := $(shell command -v clafer 2>/dev/null)
LANDO    := $(shell command -v lando 2>/dev/null)
SYSIDE   := $(shell command -v syside 2>/dev/null)
TAMARIN  := $(shell command -v tamarin-prover 2>/dev/null)
PROVERIF := $(shell command -v proverif 2>/dev/null)
CRYPTOL  := $(shell command -v cryptol 2>/dev/null)

USE_DOCKER ?= no
DOCKERIZE  := $(filter yes YES true TRUE 1,$(USE_DOCKER))

# For each tool, use Docker when forced or when the local tool is absent.
CLAFER_DOCKER  := $(if $(DOCKERIZE),1,$(if $(CLAFER),,1))
LANDO_DOCKER   := $(if $(DOCKERIZE),1,$(if $(LANDO),,1))
TAMARIN_DOCKER := $(if $(DOCKERIZE),1,$(if $(TAMARIN),,1))

ifdef CLAFER_DOCKER
  CLAFER_CMD = $(PLE_DOCKER_RUN) 'clafer $(1)'
else
  CLAFER_CMD = clafer $(1)
endif

ifdef LANDO_DOCKER
  LANDO_CMD = $(PLE_DOCKER_RUN) 'lando $(1)'
else
  LANDO_CMD = lando $(1)
endif

ifdef TAMARIN_DOCKER
  TAMARIN_BIN := $(CPV_DOCKER) tamarin-prover
else
  TAMARIN_BIN := tamarin-prover
endif

# Chocosolver: always use Docker (Java JAR is Linux/x86-only).
CHOCOSOLVER_CMD = $(PLE_DOCKER_RUN) \
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
# Formal model files
# ============================================================================

TAMARIN_MODELS  := $(wildcard *.spthy)
PROVERIF_MODELS := $(wildcard *.pv)
CRYPTOL_MODEL   := NeedhamSchroeder.cry

# Directory for CV (proof) outputs.
CV_OUTPUT := output

# ============================================================================
# Phony targets
# ============================================================================

.PHONY: all help ci cv clean bootstrap \
        ple typecheck validate \
        clafer-typecheck lando-typecheck sysml-typecheck \
        cryptol-typecheck tamarin-typecheck proverif-typecheck \
        clafer-validate tamarin-cv proverif-cv

# ============================================================================
# Default and help
# ============================================================================

all: ci cv

help:
	@echo "Needham-Schroeder Pedagogical Example"
	@echo "======================================"
	@echo ""
	@echo "  make all              Run CI + CV (default)"
	@echo "  make ci               Typecheck/well-formedness-check all specs"
	@echo "  make cv               Formal validation (Clafer + Tamarin + ProVerif)"
	@echo ""
	@echo "  make clafer-typecheck   Typecheck Clafer PLE model"
	@echo "  make lando-typecheck    Typecheck Lando domain model"
	@echo "  make sysml-typecheck    Typecheck SysMLv2 model (Sensmetry Syside)"
	@echo "  make cryptol-typecheck  Typecheck Cryptol model"
	@echo "  make tamarin-typecheck  Well-formedness of Tamarin models"
	@echo "  make proverif-typecheck Well-formedness of ProVerif models"
	@echo ""
	@echo "  make tamarin-cv         Run Tamarin proofs (writes $(CV_OUTPUT)/)"
	@echo "  make proverif-cv        Run ProVerif analyses (writes $(CV_OUTPUT)/)"
	@echo ""
	@echo "  make bootstrap        (Re)initialize PLE prelude from RDE Bootstrap"
	@echo "  make clean            Remove generated files"

# ============================================================================
# CI: Typecheck / well-formedness of all specifications
# ============================================================================

ci: clafer-typecheck lando-typecheck sysml-typecheck \
    cryptol-typecheck tamarin-typecheck proverif-typecheck

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

# Cryptol typecheck: load and typecheck the Cryptol module.
#
# No project Docker image bundles Cryptol, so this runs only when Cryptol is
# installed locally; otherwise it is skipped with a warning.  Cryptol files
# are, in any case, validated in CI by test-validity-of-cryptol-files.yml.
cryptol-typecheck: $(CRYPTOL_MODEL)
ifdef CRYPTOL
	@echo "[info] cryptol typecheck $(CRYPTOL_MODEL)"
	@cryptol -c ':load $(CRYPTOL_MODEL)' -c ':quit' >/dev/null \
	  && echo "  well-typed." \
	  || { echo "ERROR: Cryptol typecheck failed." >&2; exit 1; }
else
	@echo "WARNING: cryptol not found; skipping Cryptol typecheck."
	@echo "  Cryptol files are also validated in CI by"
	@echo "  test-validity-of-cryptol-files.yml."
endif

# Tamarin syntax check: parse each model.  This matches the project convention
# in models/cryptography/tamarin (its `syntax` target also uses --parse-only).
# We deliberately do NOT run --precompute-only wellformedness heuristics here:
# the SAPIC+-translated models emit benign "State fact occurs on LHS but not
# RHS" warnings that are an artifact of the process translation, not defects.
# Full wellformedness and proof search happen under `cv`.
tamarin-typecheck:
	@status=0; \
	for f in $(TAMARIN_MODELS); do \
	  echo "[info] tamarin-prover --parse-only $$f"; \
	  if $(TAMARIN_BIN) --parse-only "$$f" >/dev/null 2>&1; then \
	    echo "  parsed."; \
	  else \
	    echo "ERROR: Tamarin failed to parse $$f" >&2; status=1; \
	  fi; \
	done; \
	exit $$status

# ProVerif well-formedness: run ProVerif; a clean run (exit 0) means the model
# is well-formed and typed, regardless of individual query results.  No project
# Docker image bundles ProVerif, so this runs only when ProVerif is installed
# locally; otherwise it is skipped with a warning.
proverif-typecheck:
ifdef PROVERIF
	@status=0; \
	for f in $(PROVERIF_MODELS); do \
	  echo "[info] proverif $$f"; \
	  if proverif "$$f" >/dev/null 2>&1; then \
	    echo "  well-formed."; \
	  else \
	    echo "ERROR: ProVerif failed to process $$f" >&2; status=1; \
	  fi; \
	done; \
	exit $$status
else
	@echo "WARNING: proverif not found; skipping ProVerif well-formedness check."
	@echo "  No project Docker image bundles ProVerif; install it locally"
	@echo "  (e.g. brew install proverif) or provide a ProVerif-capable image."
endif

# Legacy aliases for backward compatibility.
typecheck: clafer-typecheck
validate: cv

# ============================================================================
# CV: Formal validation
#
# Runs the actual analyses and records outputs under $(CV_OUTPUT)/.  Because
# this is a pedagogical example with an intentionally INSECURE protocol variant
# alongside the fixed one, "all properties hold" is NOT the success criterion:
# the insecure models are expected to falsify some properties.  CV therefore
# runs the tools and records results, failing only on tool/execution errors.
# @todo Joe Kiniry: assert per-variant expected results (secure vs insecure).
# ============================================================================

cv: clafer-validate tamarin-cv proverif-cv

# Clafer inhabitance check via Chocosolver.
clafer-validate: needham-schroeder.cfr
	$(call CHOCOSOLVER_CMD,-n 1 --maxint 100 --minint 100 \
	  --file /work/needham-schroeder.cfr)

$(CV_OUTPUT):
	@mkdir -p $(CV_OUTPUT)

# Tamarin proofs: prove all lemmas in each model, saving output.
tamarin-cv: | $(CV_OUTPUT)
	@for f in $(TAMARIN_MODELS); do \
	  name=$$(basename "$$f" .spthy); \
	  echo "[info] tamarin-prover --prove $$f"; \
	  $(TAMARIN_BIN) --prove "$$f" > "$(CV_OUTPUT)/$$name.tamarin.txt" 2>&1 \
	    || { echo "ERROR: Tamarin execution failed on $$f" >&2; \
	         tail -20 "$(CV_OUTPUT)/$$name.tamarin.txt" >&2; exit 1; }; \
	  v=$$(grep -c 'verified' "$(CV_OUTPUT)/$$name.tamarin.txt" 2>/dev/null); \
	  x=$$(grep -c 'falsified' "$(CV_OUTPUT)/$$name.tamarin.txt" 2>/dev/null); \
	  echo "  $$name: $$v verified, $$x falsified -> $(CV_OUTPUT)/$$name.tamarin.txt"; \
	done

# ProVerif analyses: run each model, saving output.  Skipped with a warning
# when ProVerif is not installed (no project image bundles it).
proverif-cv: | $(CV_OUTPUT)
ifdef PROVERIF
	@for f in $(PROVERIF_MODELS); do \
	  name=$$(basename "$$f" .pv); \
	  echo "[info] proverif $$f"; \
	  proverif "$$f" > "$(CV_OUTPUT)/$$name.proverif.txt" 2>&1 \
	    || { echo "ERROR: ProVerif execution failed on $$f" >&2; \
	         tail -20 "$(CV_OUTPUT)/$$name.proverif.txt" >&2; exit 1; }; \
	  t=$$(grep -c 'RESULT.*is true' "$(CV_OUTPUT)/$$name.proverif.txt" 2>/dev/null); \
	  fa=$$(grep -c 'RESULT.*is false' "$(CV_OUTPUT)/$$name.proverif.txt" 2>/dev/null); \
	  echo "  $$name: $$t true, $$fa false -> $(CV_OUTPUT)/$$name.proverif.txt"; \
	done
else
	@echo "WARNING: proverif not found; skipping ProVerif analyses."
	@echo "  No project Docker image bundles ProVerif; install it locally"
	@echo "  (e.g. brew install proverif) or provide a ProVerif-capable image."
endif

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
	rm -rf $(CV_OUTPUT)
