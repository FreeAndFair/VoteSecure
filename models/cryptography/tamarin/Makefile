#######################################################
# Makefile for Tamarin model generation and checking  #
# @author Daniel M. Zimmerman (dmz@@freeandfair.us)   #
# @copyright Free & Fair                              #
# @version 0.2                                        #
#######################################################

# Resolve the Tamarin command as follows:
# - if USE_DOCKER=yes, use the CPV container unconditionally
# - otherwise use local Tamarin when present (optionally
#   override location of local Tamarin with LOCAL_TAMARIN)
# - otherwise fall back to the CPV container automatically
# - if USE_TAMARIN_RS=yes, prefer tamarin-rs to tamarin-prover
#   (either locally, if available, or in the CPV container,
#   if the CPV container is being used)
DOCKER ?= docker
USE_DOCKER ?= no
USE_TAMARIN_RS ?= yes
DOCKER_IMAGE := freeandfair/cpv-e2eviv:latest
IMAGE_PLATFORM ?=
DOCKER_PLATFORM_ARG := $(if $(strip $(IMAGE_PLATFORM)),--platform=$(strip $(IMAGE_PLATFORM)),)
ifneq ($(filter yes YES true TRUE 1,$(DOCKER)),)
$(error DOCKER must name a container engine like docker or podman; use USE_DOCKER=yes to force container-backed execution)
endif
FORCE_DOCKER := $(if $(filter yes YES true TRUE 1,$(USE_DOCKER)),yes,)
FORCE_TAMARIN_RS := $(if $(filter yes YES true TRUE 1,$(USE_TAMARIN_RS)),yes,)
LOCAL_TAMARIN ?= $(shell command -v tamarin-prover 2>/dev/null)
LOCAL_TAMARIN_RS ?= $(shell command -v tamarin-rs 2>/dev/null)
DOCKER_TAMARIN := $(DOCKER) run --rm $(DOCKER_PLATFORM_ARG) --volume "$(CURDIR):/work" --workdir /work $(DOCKER_IMAGE) tamarin-prover
DOCKER_TAMARIN_RS := $(DOCKER) run --rm $(DOCKER_PLATFORM_ARG) --volume "$(CURDIR):/work" --workdir /work $(DOCKER_IMAGE) tamarin-rs
TAMARIN := $(if $(FORCE_DOCKER),$(if $(FORCE_TAMARIN_RS),$(DOCKER_TAMARIN_RS),$(DOCKER_TAMARIN)),$(if $(FORCE_TAMARIN_RS),$(if $(LOCAL_TAMARIN_RS),$(LOCAL_TAMARIN_RS),$(DOCKER_TAMARIN_RS)),$(if $(LOCAL_TAMARIN),$(LOCAL_TAMARIN),$(DOCKER_TAMARIN))))
OPEN_CHAINS_LIMIT := 30

# M4 defines (to control proof script inclusion)
ifdef INCLUDE_PROOF_SCRIPTS
	M4_DEFINES = -DINCLUDE_PROOF_SCRIPTS
else
	M4_DEFINES =
endif

ifdef M4_DEBUG
	M4_DEBUG = --debug=V
else
	M4_DEBUG =
endif

# Display a brief help page listing possible commands/targets.
help:
	@echo "This Makefile supports the following targets:"
	@echo ""
	@echo "help (default) - display this help page"
	@echo "subprotocols   - generate the Tamarin models for all subprotocols"
	@echo "compositions   - generate Tamarin models for protocol compositions (*)"
	@echo "syntax         - check syntax of all generated models (**)"
	@echo "executability  - check executability lemmas of all generated models (**)"
	@echo "safety         - check safety lemmas of all generated models (**)"
	@echo "proofscript    - check all lemmas with included proof scripts (**)"
	@echo "ci             - regenerate models and perform syntax checks"
	@echo "cv             - regenerate models and run CV proofs/checks"
	@echo "clean          - remove all generated models and outputs"
	@echo ""
	@echo "Define the 'INCLUDE_PROOF_SCRIPTS' environment variable to include"
	@echo "proof scripts in Tamarin output, where applicable."
	@echo "Set USE_DOCKER=yes to force containerized Tamarin execution."
	@echo "Otherwise local tamarin-prover is used when available, and the"
	@echo "CPV image is used only as a fallback. Set DOCKER=<docker|podman>"
	@echo "and/or IMAGE_PLATFORM=linux/amd64 when needed."
	@echo
	@echo "(*)  - see 'compositions/README.md' for more information about"
	@echo "       what is built by this build target"
	@echo "(**) - these build targets work only on the current set of"
	@echo "       generated models (in the 'generated' directory)"

# Display the help page as the default build target.
default: help

# Target to print the Tamarin command being used.
print-tamarin:
	@echo "[info] using Tamarin command: $(TAMARIN)"

# Variables to help make find all the subprotocol sources.
SUBPROTOCOL_SOURCES = $(wildcard subprotocols/*.m4)
SUBPROTOCOL_SOURCES_NO_M4 = $(subst .spthy.m4,.spthy,$(SUBPROTOCOL_SOURCES))
SUBPROTOCOL_DESTS = $(subst subprotocols/,generated_standalone/,$(SUBPROTOCOL_SOURCES_NO_M4))

# Include files that can affect any generated subprotocol model.
SUBPROTOCOL_INCLUDES = $(wildcard subprotocols/includes/*.spthy.inc) \
                       $(wildcard subprotocols/includes/*.m4.inc) \
                       $(wildcard subprotocols/includes/proofs/*.spthy.inc) \
                       $(wildcard common/*.m4.inc) \
                       $(wildcard m4_utils/*.m4)

# Generate Tamarin models for all the subprotocols.
generated_standalone/%.spthy: subprotocols/%.spthy.m4 $(SUBPROTOCOL_INCLUDES)
	$(info [info] generating standalone model for $<...)
	@mkdir -p generated_standalone
	@m4 -E -DSTANDALONE $(M4_DEBUG) $(M4_DEFINES) $(CV_DEFINES) $< > $@

subprotocols: $(SUBPROTOCOL_DESTS)

# Variables to help make find all the composition sources.
COMPOSITION_SOURCES = $(wildcard compositions/*.m4)
COMPOSITION_SOURCES_NO_M4 = $(subst .spthy.m4,.spthy,$(COMPOSITION_SOURCES))
COMPOSITION_DESTS = $(subst compositions/,generated_composed/,$(COMPOSITION_SOURCES_NO_M4))

# Include files that can affect any generated composition model.
COMPOSITION_INCLUDES = $(SUBPROTOCOL_INCLUDES) \
											 $(wildcard other/*.spthy.inc) \
                       $(wildcard compositions/includes/*.spthy.inc) \
                       $(wildcard compositions/includes/*.m4.inc) \
                       $(wildcard compositions/includes/proofs/*.spthy.inc)

# Generate composed Tamarin models defined in 'compositions'.
generated_composed/%.spthy: compositions/%.spthy.m4 $(COMPOSITION_INCLUDES)
	$(info [info] generating model for composition $<...)
	@mkdir -p generated_composed
	@m4 -E $(M4_DEFINES) $(CV_DEFINES) $< > $@

compositions: $(COMPOSITION_DESTS)

# Execute Tamarin to check syntax of all generated models.
syntax: print-tamarin
	$(info [info] checking syntax of all generated models...)
	@$(foreach SPTHY, $(wildcard generated_standalone/*.spthy generated_composed/*.spthy), \
		$(TAMARIN) --parse-only $(SPTHY) > /dev/null || exit 1;)

# Execute Tamarin to check executability of all generated models. This
# reports an error either if Tamarin fails, or if any lemma is falsified.
executability: print-tamarin
	$(info [info] checking executability of all generated models...)
	@mkdir -p output
	$(foreach SPTHY, $(wildcard generated_standalone/*.spthy generated_composed/*.spthy), \
		$(TAMARIN) --prove="Executability*" \
		-c=${OPEN_CHAINS_LIMIT} \
		--output-dot=output/$(basename $(notdir $(SPTHY)))-executability.dot > \
		output/$(basename $(notdir $(SPTHY)))-executability.out $(SPTHY) || exit 1;)
	@grep falsified output/*.out || echo "RESULT: no lemmas falsified"
	@ ! grep -q falsified output/*.out

# Execute Tamarin to check safety lemmas for all generated models. This
# reports an error either if Tamarin fails, or if any lemma is falsified.
safety: print-tamarin
	$(info [info] checking safety of all generated models...)
	@mkdir -p output
	$(foreach SPTHY, $(wildcard generated_standalone/*.spthy generated_composed/*.spthy), \
		$(TAMARIN) --prove="Safety*" \
		-c=${OPEN_CHAINS_LIMIT} \
		--output-dot=output/$(basename $(notdir $(SPTHY)))-safety.dot > \
		output/$(basename $(notdir $(SPTHY)))-safety.out $(SPTHY) || exit 1;)
	@grep falsified output/*.out || echo "RESULT: no lemmas falsified"
	@ ! grep -q falsified output/*.out

# Execute Tamarin to check the proof scripts for all lemmas that have
# them in all generated models. This reports an error if Tamarin fails,
# or if any lemma is not marked "verified".
proofscript: print-tamarin
	$(info [info] checking proof scripts of all generated models...)
	@mkdir -p output
	$(foreach SPTHY, $(wildcard generated_standalone/*.spthy generated_composed/*.spthy), \
		$(TAMARIN) -c=${OPEN_CHAINS_LIMIT} > output/$(basename $(notdir $(SPTHY)))-proofscript.out \
		$(SPTHY) || exit 1;)
	@cat output/*-proofscript.out | grep ProofScript | grep -v NoProofScript | grep -v verified | grep -v lemma > output/combined-proofscript-results.out || echo "RESULT: all proof scripts verified"
	@cat output/combined-proofscript-results.out
	@! [ -s output/combined-proofscript-results.out ]

# Cleans up all dynamically generated files, including caches.
clean:
	$(info [info] removing all generated models and output...)
	@rm -rf generated_standalone generated_composed output

# Continuous integration/verification target.
ci: clean subprotocols compositions syntax

# Always include the proof scripts for CV
# To save execution time, we do everything at once here rather than running
# the individual executability, safety, and proofscript targets; this avoids
# doing the time-consuming Tamarin precomputations multiple times.
cv: CV_DEFINES = -DINCLUDE_PROOF_SCRIPTS
cv: print-tamarin clean subprotocols
	$(info [info] checking proof scripts, executability, and safety of all models...)
	@mkdir -p output
	$(foreach SPTHY, $(wildcard generated_standalone/*.spthy generated_composed/*.spthy), \
		time $(TAMARIN) --prove="Sources*" --prove="Safety*" --prove="Executability*" \
		--output-dot=output/$(basename $(notdir $(SPTHY))).dot > \
		output/$(basename $(notdir $(SPTHY))).out \
		$(SPTHY) || exit 1;)
	@cat output/*.out | grep ProofScript | grep -v NoProofScript | grep -v verified | grep -v lemma > output/combined-proofscript-results.out || echo "RESULT: all proof scripts verified"
	@cat output/combined-proofscript-results.out
	@grep falsified output/*.out || echo "RESULT: no lemmas falsified"
	@! [ -s output/combined-proofscript-results.out ]
	@ ! grep -q falsified output/*.out

# List of phony targets
.PHONY: default help subprotocols compositions syntax executability safety proofscript clean ci cv
