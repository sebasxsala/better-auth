# Better Auth Ruby Release Checklist

Use this checklist before cutting a Ruby gem release.

## Required Verification

- [ ] Run `make ci`.
- [ ] Run `make release-check`.
- [ ] Run `cd packages/better_auth && bundle exec rake test`.
- [ ] Run `cd packages/better_auth && bundle exec standardrb`.
- [ ] Run `cd packages/better_auth-passkey && bundle exec rake test`.
- [ ] Run `cd packages/better_auth-passkey && bundle exec standardrb`.
- [ ] Run `cd packages/better_auth-api-key && bundle exec rake test`.
- [ ] Run `cd packages/better_auth-api-key && bundle exec standardrb`.
- [ ] Run `cd packages/better_auth-rails && bundle exec rspec`.
- [ ] Run `cd packages/better_auth-rails && bundle exec standardrb`.
- [ ] Run `cd packages/better_auth-sinatra && bundle exec rspec`.
- [ ] Run `cd packages/better_auth-sinatra && bundle exec standardrb`.
- [ ] Run `cd packages/better_auth-hanami && bundle exec rspec`.
- [ ] Run `cd packages/better_auth-hanami && bundle exec standardrb`.
- [ ] Smoke test `/api/auth/ok`.
- [ ] Smoke test email/password sign-up, sign-in, get-session, and sign-out.
- [ ] Smoke test Rails mount with generated initializer and migration.
- [ ] Smoke test Sinatra mount with generated config and SQL migration.

## Documentation

- [ ] Update root `README.md` compatibility status.
- [ ] Update `packages/better_auth/README.md`.
- [ ] Update `packages/better_auth-rails/README.md`.
- [ ] Update `packages/better_auth-sinatra/README.md`.
- [ ] Update Ruby-first docs in `docs/content/docs`.
- [ ] Confirm pages that still contain upstream TypeScript examples have a Ruby port warning.
- [ ] Update `.docs/features/upstream-parity-matrix.md`.
- [ ] Update feature notes for any changed plugin or adapter behavior.

## Release Metadata

- [ ] Update gem versions.
- [ ] Update changelog or release notes.
- [ ] Confirm `better_auth-rails` and defensive alias `better_auth_rails` publish metadata.
- [ ] Confirm `better_auth-passkey` publish metadata.
- [ ] Confirm `better_auth-api-key` publish metadata.
- [ ] Confirm `better_auth-sinatra` publish metadata.
- [ ] Confirm `better_auth-hanami` publish metadata.
- [ ] Confirm each released RubyGems package trusts `.github/workflows/release.yml` for Trusted Publishing.
- [ ] Confirm the release tag uses the package prefix, for example `better_auth-v0.1.2`, `better_auth-rails-v0.1.2`, `better_auth-passkey-v0.1.2`, `better_auth-sinatra-v0.1.2`, or `better_auth-hanami-v0.1.2`.
- [ ] Confirm gemspec files include the intended files and exclude generated caches.
- [ ] Confirm no `.env`, `.next`, `node_modules`, coverage, or local database files are staged.

## Manual Smoke Flows

- [ ] Rack app can mount `BetterAuth.auth(...)` at `/api/auth`.
- [ ] Rails app can run `bin/rails generate better_auth:install`.
- [ ] Sinatra app can register `BetterAuth::Sinatra` and run `rake better_auth:generate:migration`.
- [ ] Hanami app can mount Better Auth routes and run `rake better_auth:generate:migration`.
- [ ] PostgreSQL migration creates tables, indexes, and foreign keys.
- [ ] MySQL migration or direct adapter flow runs against a local service when available.
- [ ] JavaScript client can call the Ruby server with credentials enabled.
