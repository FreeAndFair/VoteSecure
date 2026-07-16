# Vendored RDE Bootstrap PLE Prelude

These Clafer modules are the reusable RDE product-line-engineering
prelude (the abstract metamodel: specifications, requirements,
refinements, architecture, platform, environment, configuration,
product, and system).  The Needham-Schroeder concretization in
`../ple.cfr` depends on the abstract clafers defined here; neither file
typechecks on its own.  The complete model is assembled by
concatenating these modules with `../ple.cfr` (see `../Makefile`), and
that combined model is what CI typechecks.

## Provenance

Vendored from the RDE Bootstrap project:

- Repository: `git@gitlab-ext.galois.com:RDE/rde-bootstrap-project.git`
- Path: `specs/ple/`
- Source revision: `aa8d947`

To refresh from upstream, run `make bootstrap` in the parent directory
(requires a local checkout of the RDE Bootstrap project), then review
and commit the changes.
