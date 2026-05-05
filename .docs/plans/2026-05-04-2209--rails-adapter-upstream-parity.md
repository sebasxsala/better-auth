# Rails Adapter Upstream Parity Plan

**Summary**
Rails is already in decent shape from the prior hardening work: mounting, context prep, LIKE escaping, update/delete parity, joins, secrets config, and generated IDs are handled. The remaining meaningful gaps are in `BetterAuth::Rails::ActiveRecordAdapter` query/input parity versus upstream adapter behavior and the local SQL/Hanami adapters.

**Key Changes**
- [x] Update `packages/better_auth-rails/lib/better_auth/rails/active_record_adapter.rb` where handling to support `connector: "OR"` as well as the default `AND`, matching upstream adapter contract and local Mongo/Hanami behavior.
- [x] Add `mode: "insensitive"` support for string `eq`, `ne`, `in`, `not_in`, `contains`, `starts_with`, and `ends_with` predicates in ActiveRecord queries.
- [x] Align `ActiveRecordAdapter#transform_input` with SQL/Hanami behavior: reject truthy `input: false` fields unless `force_allow_id`, enforce required create fields, parse date strings, and preserve existing default/on-update behavior.
- [x] Add output coercion for ActiveRecord records where needed so booleans, date strings, and JSON-like values are normalized consistently with the core SQL adapter.
- [x] Keep this Rails-scoped; do not broaden into Hanami/SQL refactors unless tests expose a shared helper worth extracting.

**Tests**
- [x] Add ActiveRecord adapter unit specs for `OR` where clauses using a fake relation or real ActiveRecord relation.
- [x] Add PostgreSQL and MySQL integration assertions for `mode: "insensitive"` across equality, `in`/`not_in`, and LIKE-style operators.
- [x] Add specs proving `input: false` truthy values are rejected on direct adapter calls and required create fields fail before database constraint errors.
- [x] Run `rbenv exec bundle exec rspec spec/better_auth/rails/active_record_adapter_spec.rb`.
- [x] Run database-backed Rails specs when services are available: `rbenv exec bundle exec rspec spec/better_auth/rails/postgres_integration_spec.rb spec/better_auth/rails/mysql_integration_spec.rb`.
- [x] Run `rbenv exec bundle exec standardrb`.

**Assumptions**
- Save the plan under `.docs/plans/`, not `.docs/plan`, because root `AGENTS.md` explicitly requires `.docs/plans/YYYY-MM-DD-HHMM--short-name.md`.
- No gem version bump for this unreleased hardening work.
- Existing unrelated deleted `.docs/plans/*` files in the worktree are not part of this task and should not be restored or removed by this work.
