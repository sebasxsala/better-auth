# AI assistant guidance

## Required context

Before making changes in this repository, read the relevant agent instructions:

- Core gem instructions: `packages/better_auth/AGENTS.md` when editing `packages/better_auth/`
- Rails adapter instructions: `packages/better_auth-rails/AGENTS.md` when editing `packages/better_auth-rails/`
- Read how upstream tests are written
- Read how upstream related implementations are written

## Plans

Long-running implementation plans live in `.docs/plans/`.

Current master plan:

All future implementation plans should be created in `.docs/plans/` using the filename format `YYYY-MM-DD-short-name.md`.

Plans should use checkbox steps so agents can mark progress as work is completed. When an agent completes a phase, discovers a meaningful difference from upstream, or chooses a Ruby-specific adaptation, it should update the relevant plan.

## Upstream source of truth

The `upstream/` submodule is the source of truth for Better Auth behavior. Before porting or modifying a feature, inspect the matching upstream source and tests, then adapt that behavior into Ruby.

## Testing

- Avoid mocks unless the real dependency is truly impractical
- Test actual behavior, not implementation details
- Check upstream tests (`upstream/packages/better-auth/src/**/*.test.ts`) for test case ideas
- Database tests are preferred over in-memory tests

## Versioning and releases

Ruby package versions are independent per gem. Do not bump every package just because
one package changed, and do not bump versions for ordinary unreleased commits.

When preparing a publishable release, update only the package version files for the
gems being released. Choose the version bump from that package's public behavior:

- Patch (`0.1.0` -> `0.1.1`) for compatible bug fixes, documentation or metadata
  corrections, CI/release fixes, and internal changes that do not add public API.
- Minor (`0.1.1` -> `0.2.0`) for new public behavior, new options, new endpoints,
  new package capabilities, or breaking public API changes while the package is
  still pre-`1.0`.
- Major (`1.2.3` -> `2.0.0`) only after a package has reached `1.0` and a release
  intentionally breaks its public API.

Use prerelease versions such as `0.2.0.beta.1` when a feature should be published
for validation before a stable release. The release tag must match the target
package version exactly.
