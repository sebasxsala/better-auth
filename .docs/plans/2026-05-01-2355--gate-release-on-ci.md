# Gate release publishing on CI

## Context

Upstream Better Auth keeps release automation separate from CI, but its CI workflow has a final aggregate `ci` job that depends on the main quality gates and fails unless every dependency is green. The upstream release flow is Changesets-based and branch-driven, while this Ruby port publishes gems from package-prefixed tags.

Ruby-specific adaptation: keep tag-driven gem releases, add the upstream-style aggregate `ci` check to the CI workflow, and make the release workflow verify that the tagged commit already has a successful `CI / ci` check before any `gem push` job can run.

## Steps

- [x] Review local CI and release workflows.
- [x] Review upstream CI and release workflows under `upstream/.github/workflows/`.
- [x] Add an upstream-style aggregate `ci` job to `.github/workflows/ci.yml`.
- [x] Add a release gate that waits for `CI / ci` on the tagged commit and fails publishing if the check is missing or failed.
- [x] Make all gem publish jobs depend on the CI gate.
- [x] Preserve dry-run/manual validation behavior without requiring prior CI.
- [x] Validate workflow syntax by parsing the changed YAML files.
