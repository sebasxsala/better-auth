# AI assistant guidance

See the root `AGENTS.md`.

This package is the Sinatra integration layer. Keep authentication behavior in
`packages/better_auth`; this package should only provide Sinatra mounting,
helpers, SQL migration tasks, docs, and tests.
