###############################################
# Assurance Case Makefile, © 2025 Free & Fair #
# Daniel M. Zimmerman, May 2025               #
###############################################

# Definitions

NXT_DIR :=          ../models/threat-model/src
SKELETON_DIR :=     ./advocate-project
PARSE_CMD :=        ${DB_DIR}/parse.py
GEN_SKELETON_CMD := PYTHONPATH="${PYTHONPATH}:${NXT_DIR}" scripts/generate_advocate_skeleton.py

# Default target: show the help
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid build targets are:"
	@echo "help (default)        - display this help page"
	@echo ""
	@echo "skeleton         - (re)generate the AdvoCATE assurance case skeleton"
	@echo "skeleton_implied - (re)generate the AdvoCATE assurance case skeleton,"
	@echo "                   including implied security objectives (e.g., an"
	@echo "                   attack against objective C3.1 is also treated as an"
	@echo "                   attack against properties C3, C3.1.1, C3.1.2)"
	@echo ""
	@echo "    Note that the skeleton targets overwrite any manual changes to the"
	@echo "    skeleton files, but leave other AdvoCATE project files untouched."
	@echo ""
	@echo "update           - update the non-argument parts of the assurance case"
	@echo "                   skeleton from the latest threat model"
	@echo "update_implied   - update the non-argument parts of the assurance case"
	@echo "                   skeleton from the latest threat model, including"
	@echo "                   implied security objectives"
	@echo ""
	@echo "    The update targets update all the skeleton files except the argument,"
	@echo "    but leave other AdvoCATE project files untouched."
	@echo ""

# Build the AdvoCATE skeleton files
skeleton:
	@echo "generating AdvoCATE skeleton"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} ${SKELETON_DIR}

# Build the AdvoCATE skeleton files with implied security objectives included
skeleton_implied:
	@echo "generating AdvoCATE skeleton with implied security objectives"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --implied ${SKELETON_DIR}

# Build the non-argument AdvoCATE skeleton files
update:
	@echo "updating static parts of AdvoCATE skeleton"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --no-argument ${SKELETON_DIR}

# Build the non-argument AdvoCATE skeleton files with implied security
# objectives included
update_implied:
	@echo "updating static parts of AdvoCATE skeleton with implied security objectives"
	mkdir -p ${SKELETON_DIR}
	${GEN_SKELETON_CMD} --no-argument --implied ${SKELETON_DIR}

ci: skeleton skeleton_implied update update_implied

PHONY: all help skeleton skeleton_implied update update_implied ci
