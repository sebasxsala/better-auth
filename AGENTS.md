# AI assistant guidance

## Required context

Before making changes in this repository, read the relevant agent instructions:

- Core gem instructions: `packages/better_auth/AGENTS.md` when editing `packages/better_auth/`
- Rails adapter instructions: `packages/better_auth-rails/AGENTS.md` when editing `packages/better_auth-rails/`

## Plans

Long-running implementation plans live in `.docs/plans/`.

Current master plan:

- Better Auth Ruby full port: `.docs/plans/2026-04-25-better-auth-ruby-port.md`

All future implementation plans should be created in `.docs/plans/` using the filename format `YYYY-MM-DD-short-name.md`.

Plans should use checkbox steps so agents can mark progress as work is completed. When an agent completes a phase, discovers a meaningful difference from upstream, or chooses a Ruby-specific adaptation, it should update the relevant plan.

## Upstream source of truth

The `upstream/` submodule is the source of truth for Better Auth behavior. Before porting or modifying a feature, inspect the matching upstream source and tests, then adapt that behavior into Ruby.

For the Better Auth Ruby port, always read `.docs/plans/2026-04-25-better-auth-ruby-port.md` before implementation work.
