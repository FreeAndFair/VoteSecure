##########################################################
# Threat Model Makefile, © 2025 Free & Fair              #
# Daniel M. Zimmerman, January 2025                      #
##########################################################
# Possible commands are: make [all|db|latex|pdf|clean

# Definitions

LATEXMK_CMD :=      latexmk --pdf
LATEX_INPUTS :=     ./latex_inputs
SRC_DIR :=          ./src
DIAGRAMS_DIR :=			./diagrams
VIEW_CMD :=         python -m nxt.model.view_cli
GEN_LATEX_CMD :=    python -m nxt.model.generate_latex_inputs
SERVER_CMD :=       python -m nxt.model.server
GRAPH_CMD :=        python -m nxt.model.visualize
GRAPH_FILE :=       threat-model.html
PID_FILE :=         server.pid
BROWSER_CMD :=      open
SERVER_LOC :=       http://localhost:8911
THREAT_MODEL_DOC := threat-model

# Default target: show the help
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid targets are:"
	@echo "help (default) - display this help page"
	@echo "latex          - generate all LaTeX inputs"
	@echo "pdf            - build the threat model PDF"
	@echo "view           - run a smoketest of the command-line view of the model"
	@echo "server         - run the server-based view of the threat model"
	@echo "stop           - stop the running server supporting the server-based view of the threat model"
	@echo "graph          - run the graph-based view of the threat model"
	@echo ""
	@echo "clean          - remove all generated files"
	@echo ""
	@echo "This Makefile assumes the diagrams are up to date, as they are"
	@echo "included in the repository. To rebuild the diagrams after changes,"
	@echo "use the Makefile in ${DIAGRAMS_DIR}"
	@echo ""

# Build static representations
static: pdf graph

# Build the LaTeX inputs
latex:
	@echo "generating LaTeX inputs"
	mkdir -p ${LATEX_INPUTS}
	PYTHONPATH=${SRC_DIR} ${GEN_LATEX_CMD} --output ${LATEX_INPUTS}

# Build the PDF, including generating its dependencies
pdf: latex ${THREAT_MODEL_DOC}.tex references.bib
	@echo "generating threat model PDF"
	${LATEXMK_CMD} -halt-on-error -synctex=1 ${THREAT_MODEL_DOC}.tex

# Run a single smoketest of the command-line view of the model.
view:
	@echo "running an example view of the threat model"
	PYTHONPATH=${SRC_DIR} ${VIEW_CMD} -e attack -r "clash_attack_v2" -t

# Run the threat model server, then open a browser window.
server:
	@echo "running the threat model server for the server-based viewer"
	bash -c "PYTHONPATH=${SRC_DIR} ${SERVER_CMD} & echo \$$! > ${PID_FILE};"
	${BROWSER_CMD} ${SERVER_LOC}

# Stop the threat model server.
stop:
	@echo "shutting down the threat model server"
	@if [ -f ${PID_FILE} ]; then \
		kill `cat $(PID_FILE)` && rm -f $(PID_FILE); \
	else \
		echo "the server is not running (no PID file found)"; \
	fi

# Build the HTML graph representation
graph:
	@echo "generating graph representation"
	PYTHONPATH=${SRC_DIR} ${GRAPH_CMD} -o ${GRAPH_FILE}

# Clean the directory
clean:
	rm -rf ${LATEX_INPUTS}
	rm -f ${THREAT_MODEL_DOC}.pdf ${GRAPH_FILE}
	${LATEXMK_CMD} -bibtex-cond1 -C ${THREAT_MODEL_DOC}.tex

PHONY: all help db latex pdf view browser stop clean
