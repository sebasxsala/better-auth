# AGENTS.md

Better Auth Ruby is a Ruby port of the [better-auth](https://github.com/better-auth/better-auth) TypeScript authentication framework. It follows the same philosophy, architecture, and API design as the original JS library, translated idiomatically to Ruby with first-class Rails support.

- The default branch is `canary` (development). `main` is for stable releases.
- Prefer automation: execute requested actions without confirmation unless blocked by missing info or safety concerns.
- You may be running in a git worktree. All changes must be made in your current working directory.
- Before making changes to a package, **check if that package has its own `AGENTS.md`** for package-specific guidance.

## Project Philosophy

This is **not** a reimagination -- it is a faithful translation. The JS upstream (`upstream/`) is the source of truth for behavior, API surface, and architecture. When implementing a feature:

1. Read the upstream TypeScript implementation first
2. Translate it to idiomatic Ruby, preserving the same logic and flow
3. Match the same API naming where possible (adapted to Ruby conventions: `snake_case` methods, `CamelCase` modules)
4. Maintain feature parity -- if upstream has it, we should too

## Build and Dev

- **Install**: `make install` or `bundle install` from root
- **Lint**: `make lint` (StandardRB across all packages)
- **Lint fix**: `make lint-fix`
- **Test all**: `make ci` or `bundle exec rake ci`
- **Test core only**: `make test-core` (Minitest)
- **Test Rails only**: `make test-rails` (RSpec)
- **Console**: `make console` (IRB with all packages loaded)
- **DB containers**: `make db-up` / `make db-down` (PostgreSQL, MySQL, Redis)

### Working in a Specific Package

```bash
cd packages/better_auth
bundle install
bundle exec rake test
```

## Monorepo Structure

Ruby workspace with Bundler. Two gems + upstream reference:

| Path | Name | Purpose |
|------|------|---------|
| `packages/better_auth/` | `better_auth` | Core authentication library. Framework-agnostic, Rack-based. This is where most work happens. |
| `packages/better_auth-rails/` | `better_auth-rails` | Rails adapter. Middleware, controller helpers, generators. Depends on `better_auth`. |
| `upstream/` | -- | Git submodule of the original TypeScript better-auth. Read-only reference for translation work. |

### Why `upstream/` Lives at Root

The `upstream/` folder is a git submodule (`git@github.com:better-auth/better-auth.git`) that serves as the translation reference. It is **not** a Ruby package and does not belong in `packages/`. Keeping it at root clearly separates "our code" (`packages/`) from "the reference" (`upstream/`).

### Key Files

| File | Purpose |
|------|---------|
| `Gemfile` | Workspace Gemfile, references both packages as path gems |
| `Rakefile` | Workspace tasks: `ci`, `install`, `lint`, `test` |
| `Makefile` | Developer-friendly shortcuts for common operations |
| `.gitmodules` | Submodule config pointing upstream to better-auth JS |

## Versioning Strategy

### Our Versions (Ruby gems)

We follow semver with branch-based version management:

| Branch | Purpose | Example |
|--------|---------|---------|
| `canary` | Active development. All PRs target this branch. | `0.2.0-canary.1` |
| `main` | Stable releases. Merges from `canary` when ready. | `0.2.0` |
| `v0.x` | Latest of the 0.x line (current) | |
| `v1.0.x` | Will be created when 1.0 ships | |
| `v1.1.x` | Future minor version branch | |

**Branch naming rules:**
- Major and minor versions get their own branch: `v1.0.x`, `v1.1.x`, `v2.0.x`
- The `.x` suffix means "latest patch of this version"
- Patch versions do NOT get their own branch -- they are features/fixes that merge into the minor branch
- `canary` is always the bleeding edge

**Current status:** Working on `0.x` (pre-release). First public release will establish the `v0.x` branch.

### Upstream Versions (JS reference)

The upstream submodule currently tracks **v1.4.x** of the JS better-auth. When a new upstream version is released:

1. Update the submodule: `cd upstream && git fetch && git checkout v1.5.x && cd ..`
2. Review the diff between the old and new upstream versions
3. Port relevant changes to the Ruby codebase
4. Document what was ported in the commit/PR

## Upstream Sync Process

We regularly sync with the JS upstream to maintain feature parity.

### Updating the Upstream Reference

```bash
cd upstream
git fetch origin
git checkout <new-version-tag-or-branch>
cd ..
git add upstream
git commit -m "chore: update upstream to <version>"
```

### Porting Changes

When upstream updates:

1. **Diff the upstream**: Compare the old and new submodule commits to see what changed
2. **Identify relevant changes**: Not everything applies (JS-specific tooling, bundler config, etc.)
3. **Translate to Ruby**: Port the logic, not the syntax. Use Ruby idioms.
4. **Test thoroughly**: Every ported feature needs tests that verify the same behavior as upstream
5. **Reference the upstream**: In PR descriptions, link to the upstream commits/PRs being ported

### What to Port vs Skip

**Port:**
- Core auth logic (session management, token handling, OAuth flows, etc.)
- Plugin implementations
- API route handlers
- Database adapter interfaces
- Security fixes

**Skip:**
- JS build tooling (turbo, biome, etc.)
- TypeScript type definitions (translate to Ruby type signatures/YARD docs)
- Frontend client code
- JS-specific framework adapters (Next.js, Svelte, etc.)
- npm/pnpm configuration

## Style Guide

- **Linter**: StandardRB (enforced in CI)
- **Ruby version**: >= 3.2.0 (development on 3.3.6)
- **Indentation**: 2 spaces
- **String literals**: Prefer single quotes unless interpolation is needed
- **Frozen string literal**: Always add `# frozen_string_literal: true` pragma

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Files/directories | `snake_case` | `oauth_provider.rb` |
| Classes/Modules | `CamelCase` | `BetterAuth::OAuthProvider` |
| Methods/variables | `snake_case` | `validate_token` |
| Constants | `SCREAMING_SNAKE_CASE` | `DEFAULT_EXPIRY` |
| Gem names | `snake_case` with hyphens for namespacing | `better_auth-rails` |

### Code Principles

- Prefer composition over inheritance
- Keep methods short and focused
- Avoid `try`/`rescue` where possible -- let errors propagate unless you have a specific recovery strategy
- Never leave a `rescue` block empty
- Prefer early returns over nested conditionals
- Avoid unnecessary metaprogramming

### Avoid Mutable State

Prefer `freeze` and immutable patterns:

```ruby
# Good
DEFAULTS = {expires_in: 3600, algorithm: "HS256"}.freeze

# Bad
DEFAULTS = {expires_in: 3600, algorithm: "HS256"}
```

## Testing

**All code must have tests. No exceptions.**

### Testing Philosophy

- **Avoid mocks** as much as possible. Test real implementations with real flows.
- Only use mocks/stubs when the real dependency is truly impractical (external HTTP APIs, time-sensitive operations).
- Tests must verify actual behavior, not duplicate implementation logic.
- If you find yourself mocking more than one thing in a test, reconsider the test design.

### Test Frameworks

| Package | Framework | Directory | Run Command |
|---------|-----------|-----------|-------------|
| `better_auth` | Minitest | `test/` | `bundle exec rake test` |
| `better_auth-rails` | RSpec | `spec/` | `bundle exec rspec` |

### Test File Naming

- Minitest: `test/<module_path>_test.rb` (e.g., `test/better_auth/session_test.rb`)
- RSpec: `spec/<module_path>_spec.rb` (e.g., `spec/better_auth/rails/middleware_spec.rb`)

### What Good Tests Look Like

```ruby
# Good: tests real behavior
def test_creates_session_with_valid_credentials
  user = create_user(email: "test@example.com", password: "secure123")
  session = BetterAuth::Session.create(email: user.email, password: "secure123")

  assert session.valid?
  assert_equal user.id, session.user_id
end

# Bad: mocks everything, tests nothing real
def test_creates_session
  user = mock("user")
  user.expects(:id).returns(1)
  BetterAuth::Session.expects(:create).returns(mock_session)
  # This tests your mocks, not your code
end
```

## Commit Conventions

[Conventional Commits](https://www.conventionalcommits.org/) with scopes matching packages:

| Scope | Package |
|-------|---------|
| `core` | `packages/better_auth` |
| `rails` | `packages/better_auth-rails` |
| (no scope) | Cross-package or workspace-level changes |

```
feat(core): add OAuth2 provider support
fix(rails): resolve middleware ordering issue
chore: update upstream to v1.4.22
docs: improve README installation guide
test(core): add session expiry integration tests
```

## Pull Requests

- PRs target `canary` (never `main` directly)
- PR descriptions: 2-3 lines covering **what** changed and **why**
- Reference upstream commits/PRs when porting features
- Include test coverage for all changes
- Ensure `make ci` passes before requesting review

## Git Workflow

```
canary (development)
  |
  |-- feat/oauth-provider (feature branches)
  |-- fix/session-expiry
  |
  v
main (stable releases)
  |
  |-- v0.x (version branches, created at release time)
  |-- v1.0.x (future)
```

### Branch Rules

1. Create feature branches from `canary`
2. PR into `canary`
3. When `canary` is stable, merge to `main` and tag a release
4. Create version branches (`v0.x`, `v1.0.x`) from release tags

## Per-Package AGENTS.md

Each package may have its own `AGENTS.md` with package-specific guidance. **Always check these before working in a package:**

- `packages/better_auth/AGENTS.md` -- Core library specifics, Minitest patterns, Rack-only constraints
- `packages/better_auth-rails/AGENTS.md` -- Rails adapter specifics, RSpec patterns, Rails version support

## After Every Change

1. Run `bundle exec standardrb` -- must pass with zero violations
2. Run the relevant test suite -- all tests must pass
3. If you changed the public API, update YARD documentation
4. **Do NOT commit unless explicitly asked to**
