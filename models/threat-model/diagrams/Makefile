########################################################
# Makefile to build threat model diagrams, © Free&Fair #
# Daniel M. Zimmerman, October 2024                    #
########################################################
# Possible commands are: make [all|seq|overview

# Definitions

PLANTUML := "plantuml"
# the above works for Homebrew-installed PlantUML; alternatively:
# PLANTUML := "java -Djava.awt.headless=true -jar /path/to/plantuml.jar"

UMLSEQDIAGRAMS := $(wildcard seq*.uml)
PNGSEQDIAGRAMS := $(UMLSEQDIAGRAMS:.uml=.png)
PDFSEQDIAGRAMS := $(UMLSEQDIAGRAMS:.uml=.pdf)

# Default target: build all the diagrams
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid targets are:"
	@echo "make seqpng   - build all PNG sequence diagrams"
	@echo "make seqpdf   - build all PDF sequence diagrams"
	@echo "                (requires Inkscape)"
	@echo "make seqX.png - build a single sequence diagram X"
	@echo "make seqX.pdf - build a single PDF sequence diagram X"
	@echo "                (requires Inkscape)"
	@echo "make overview - build the overview diagram"
	@echo "                (requires macOS and OmniGraffle)"
	@echo "make clean    - remove all diagrams"
	@echo "make help     - display this help page"

# Build a single sequence diagram
seq%.png: seq%.uml
	@echo "generating $@"
	@$(PLANTUML) $<

seq%.pdf: seq%.uml
	@echo "generating $@"
	cat $< | $(PLANTUML) -tsvg -p | inkscape --pipe --export-filename=$@

seqpng: $(PNGSEQDIAGRAMS)

seqpdf: $(PDFSEQDIAGRAMS)

system-overview.pdf: system-overview.graffle
	@echo "exporting system overview from OmniGraffle"
	open system-overview.graffle
	osascript omnigraffle-export.applescript

overview: system-overview.pdf

clean:
	rm -f $(PNGSEQDIAGRAMS)
	rm -f $(PDFSEQDIAGRAMS)
	rm -f $(OVERVIEWDIAGRAM)

PHONY: all help seq overview
