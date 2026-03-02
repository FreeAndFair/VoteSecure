RDE_BOOTSTRAP := /Users/kiniry/Sandboxes/RDE/rde-bootstrap-project/specs/ple

.PHONY: all ple typecheck validate

all: ple typecheck validate

bootstrap:
	rm -rf ple
	cp -r $(RDE_BOOTSTRAP) .

ple: needham-schroeder.cfr

needham-schroeder.cfr: ple.cfr ple/prelude.cfr ple/configuration.cfr ple/environment.cfr ple/platform.cfr ple/product.cfr ple/refinements.cfr ple/requirements.cfr ple/specifications.cfr ple/system.cfr
	cat \
	  ple/prelude.cfr \
	  ple/architecture.cfr \
	  ple/configuration.cfr \
	  ple/environment.cfr \
	  ple/platform.cfr \
	  ple/product.cfr \
	  ple/refinements.cfr \
	  ple/requirements.cfr \
	  ple/specifications.cfr \
	  ple/system.cfr \
	  ple.cfr > needham-schroeder.cfr

typecheck: ple
	clafer -v needham-schroeder.cfr

validate: ple
	java -jar chocosolver.jar -n 1 --maxint 100 --minint 100 --file needham-schroeder.cfr
