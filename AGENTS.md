# AI assistant guidance

## Required context

Before making changes in this repository, read the relevant agent instructions:

- When editing a package, check for a package-level `AGENTS.md` and follow it if present.
- Read how upstream related implementations are written

## Plans

All future implementation plans should be created in `.docs/plans/` using the filename format `YYYY-MM-DD-HHMM--short-name.md`.

Plans should use checkbox steps so agents can mark progress as work is completed. When an agent completes a phase, discovers a meaningful difference from upstream, or chooses a Ruby-specific adaptation, it should update the relevant plan.

## Upstream source of truth

Use the `upstream/` submodule as the source of truth for Better Auth behavior.
Before porting or changing a feature, review matching upstream source and tests,
then adapt to Ruby.

In git worktrees, `upstream/` can be empty until submodules are initialized.
Only initialize it when needed. Target upstream version: `v1.6.9`.

```bash
git submodule update --init --recursive upstream
cd upstream
git fetch --tags origin
git checkout v1.6.9
cd ..
```

If this changes the recorded submodule pointer, treat it as an intentional repo
change and include it in the related plan or PR.

## Testing

- Avoid mocks unless the real dependency is truly impractical
- Test actual behavior, not implementation details
- Check upstream tests (`upstream/**/*.test.ts`) for test case ideas
- Database tests are preferred over in-memory tests

## Versioning and releases

Version each gem independently.

- Only bump versions for gems you are releasing.
- Do not bump versions for normal unreleased commits.

Choose bump type by public impact:

- Patch (`0.1.0` -> `0.1.1`): backward-compatible fixes and internal/docs/CI updates.
- Minor (`0.1.1` -> `0.2.0`): new public behavior/options/endpoints, and breaking public changes while still pre-`1.0`.
- Major (`1.2.3` -> `2.0.0`): breaking public API changes after `1.0`.

Use prerelease versions (for example, `0.2.0.beta.1`) for validation before stable release. Release tag must exactly match the package version.
