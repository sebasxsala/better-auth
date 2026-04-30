# Dub Plugin Implementation Plan

**Goal:** Port the Dub Better Auth plugin into the Ruby core gem, with lead tracking, OAuth account linking, tests, and adapted docs.

**Upstream references checked:**
- Better Auth v1.6.9 docs: `upstream/docs/content/docs/plugins/dub.mdx`
- Published implementation: `@dub/better-auth` 0.0.6 from npm
- Public docs: `https://better-auth.com/docs/plugins/dub`

**Ruby adaptation:** Keep the plugin in `packages/better_auth` and do not add the `dub` gem as a runtime dependency. The plugin accepts a duck-typed `dub_client`, so users can install and pass the Ruby Dub SDK only when they need it.

- [x] Create a non-canary branch for the work.
- [x] Initialize upstream and inspect the Dub docs/source.
- [x] Update database hook context propagation so user-create after hooks receive the endpoint context.
- [x] Add Dub plugin tests covering default lead tracking from `dub_id`, disabled lead tracking, custom lead tracking, missing OAuth configuration, and Dub OAuth link URL generation.
- [x] Implement `BetterAuth::Plugins.dub` with `id: "dub"`, `/dub/link`, Dub OAuth defaults, lead tracking defaults, cookie cleanup, and logger-based error swallowing for Dub API failures.
- [x] Pass request context into email and social signup user creation paths so lead tracking can run in real signup flows.
- [x] Replace hidden placeholder docs at `docs/content/docs/plugins/dub.mdx` with Ruby-specific usage and option docs.
- [x] Add Dub to the Plugins sidebar under an `Others` subgroup.
- [x] Run focused Minitest files and StandardRB on changed Ruby files.
- [x] Run the full `packages/better_auth` Minitest suite and full StandardRB.
