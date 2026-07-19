# NINJA Fixed-Base PLE Meta-Model

These Clafer modules are the reusable **NINJA** (Rigorous Digital
Engineering) product-line-engineering meta-model: the abstract type
structure for a system's specifications, requirements, refinements,
architecture, assurance case, platform, environment, configuration,
product, and top-level system composition. A concrete project (here, the
Needham-Schroeder example in `../ple.cfr`) *concretizes* these abstract
clafers.

Neither the modules nor `../ple.cfr` typecheck on their own; the complete
model is assembled by concatenating the modules with `../ple.cfr` (see
`../Makefile`). That combined model is what CI typechecks (`make ci`), and
`make cv` runs it through Chocosolver, which **generates an instance**
(the model is inhabited).

## Modules

| Module | Contents |
|---|---|
| `prelude.cfr` | Executive summary; traceability core (`NamedElement`, `TraceableElement`, `URL`); `ProgLanguage` / `SpecLanguage` taxonomies |
| `platform.cfr` | Development/target platform: ISAs, CPUs, boards, compilers, OSes, simulators/emulators, HDLs, security extensions (CHERI, …), and the AI inference substrate HOARDE runs on |
| `environment.cfr` | Build, package, DevSecOps, dev, and formal-methods toolchains; frameworks |
| `specifications.cfr` | `Spec` and the kinds of specification, each constrained to its permitted `SpecLanguage`s |
| `requirements.cfr` | Informal / semi-formal / formal requirements and `Requirements` ownership aggregates |
| `refinements.cfr` | Refinement relationships, status, and rigor |
| `architecture.cfr` | Generic `System` / `Subsystem` / `Component` / `Flow` architecture |
| `assurancecase.cfr` | Assurance case: CLARISSA / Assurance 2.0 nodes + SRI Evidential Tool Bus |
| `product.cfr` | Product under development and its bills of materials |
| `configuration.cfr` | Build system, CI, CD, CV |
| `system.cfr` | `SystemSpecification` — the top-level composition of all of the above |

## Modeling conventions (required for the Chocosolver backend)

These come from the string-handling variant study in
`../variants/COMPARISON.md`; they are correctness/robustness requirements
for the Chocosolver backend, not style preferences.

1. **`->` for every primitive attribute** (`string` / `integer`); reserve
   `:` for *containment* of a user-defined clafer type (e.g.
   `version : VersionInfo`).
2. **Never inline a constraint on a declaration.** Declaration and each
   `[ … ]` constraint go on their own indented lines. An inline constraint
   throws `IllegalIntException` in Chocosolver's `buildRefPointers`.
3. **Never use a multi-valued string set** (`-> string *`, or a set literal
   `[ x = "a", "b" ]`). Chocosolver int-encodes strings and cannot hold a
   set of more than one string on one reference. Single-valued strings scale
   fine (validated past N = 320).
4. **Keep single-valued, human-readable fields as strings** (`name`,
   `referrant`, `id`, `text`).
5. **Use value-carrying `URL` handles for the one set-valued trace field,
   `url`** — `abstract URL` with a single-valued `value -> string`. An
   element that traces to several locations references several handles
   (`[ url = u_a, u_b ]`) while each URL string stays in-model.
6. **Trace data lives on `TraceableElement`, not `NamedElement`.** The trace
   triple `url` / `referrant` / `line_no` is on `TraceableElement`; only
   `name` is on `NamedElement`, so merely-named things (tools, languages)
   carry no trace data and Alloy/Chocosolver universes stay small.
7. **Own set-valued collections of subtype instances via containment (`:`),
   not references (`->`).** See the caveat below; this is why the
   `Requirements.requirements` collection nests its members.

## Backend caveat: references to subtype instances

Chocosolver (the default Choco backend) cannot inhabit a **multi-valued
reference (`->`) of cardinality ≥ 2 whose referenced atoms are declared at a
*proper subtype* of the reference's declared type** — it reports
`Generated 0 instance` even though the model is satisfiable (the **Alloy
backend, `claferIG`, generates the same model**). It is a backend
incompleteness in how references are refined across inheritance, not a
Clafer-language limitation. Minimal reproducer:

```clafer
abstract Base
abstract Mid : Base
abstract Leaf : Mid
i1 : Leaf   // i2 : Leaf … i9 : Leaf

abstract Group
  items -> Base *          // field typed at an ANCESTOR of the atoms

g : Group
  [ items = i1, i2, i3 ]   // atoms are Leaf  ->  Generated 0 instance
```

`items -> Leaf` (exact type) generates fine at any cardinality; a same-type
set of 9 is not a problem — only the *subtype* mismatch is. Tracked upstream
as [gsdlab/chocosolver#32](https://github.com/gsdlab/chocosolver/issues/32)
and [gsdlab/clafer#89](https://github.com/gsdlab/clafer/issues/89); see the
Choco backend encoding in Liang, *Solving Clafer Models with Choco* (2012).

**How this meta-model avoids it:** the `Requirements.requirements`
collection is an **ownership (containment) set** — a `Requirements`
aggregate owns its member requirements as nested children — so no
subtype-refined reference is needed. The `informal` / `semiFormal` /
`formal` fields remain references because they point at direct instances of
their declared types.

## Writing a concretization

A project model (like `../ple.cfr`) typically:

1. Declares its trace `URL` handles once, each with its `value`.
2. Declares its `Spec`s (each with a `language`, `referrant`, `line_no`, and
   one or more `url` handles).
3. Declares its `Requirements` aggregate and **nests** its member
   requirements (subtypes of `InformalRequirement` / `SemiformalRequirement`
   / `FormalRequirement`) under the `requirements` containment, wiring their
   `satisfiedBy` / `refinedBy` trace links.
4. Declares `Refinement`s between specs.
5. Declares the feature model and the top-level `System` composition.

## Validation

- `make ci` → `clafer` typechecks the assembled model.
- `make cv` → Chocosolver generates an instance (inhabitance).

## Provenance

Derived from the RDE Bootstrap project
(`git@gitlab-ext.galois.com:RDE/rde-bootstrap-project.git`, `specs/ple/`)
and revised in-repo (RDE→NINJA rename, trace-representation hybrid,
assurance-case module, platform/enumeration expansion, requirements
ownership model). The string-handling study that produced the modeling
conventions above lives in `../variants/` (`COMPARISON.md`).
