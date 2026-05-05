# Sinatra integration & adapter hardening — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden `better_auth-sinatra` end-to-end: correct Rack mount routing for nested `SCRIPT_NAME`/`PATH_INFO`, reject the unsafe `at: "/"` mount, narrow migration error handling and improve SQL splitting, align Sinatra configuration with core (`secrets`), improve operator visibility (duplicate `better_auth`, clearer Rake output), and return JSON-shaped 401s for JSON clients when appropriate. Document deployment caveats that cannot be fixed purely in code.

> **Plan corrections applied (agent review):**
> - **Task 1:** Fixed `mount_matches?` and `mounted_path_info` to support both natural Sinatra nested mounts (app under a parent `Rack::URLMap`) and Rails-engine-style mounts (app at the same path as auth). Added a second test and defense-in-depth `/` guard.
> - **Task 3:** Added the missing `missing_schema_migrations_table?` helper implementation and `MISSING_MIGRATIONS_TABLE_MESSAGES` regex list.
> - **Task 7:** Replaced naive `HTTP_ACCEPT.include?` with `request.preferred_type` guidance for robust JSON detection.
> - **Task 8:** Flagged the `generate:migration` removal as a breaking change requiring CHANGELOG/README callout.
> - **Task 9:** Clarified mount path semantics for both nested-mount patterns.
>
> **Implementation update 2026-05-05:** Implemented the Sinatra hardening items that matched core/upstream behavior. `secrets` uses the core versioned format (`[{version:, value:}]`). The duplicate Rake wiring was removed after confirming it redefined `better_auth:generate:migration` inside the namespace rather than providing a separate top-level task.

**Architecture:** `BetterAuth::Sinatra::MountedApp` decides delegation using the combined logical path `SCRIPT_NAME + PATH_INFO` and forwards to `BetterAuth::Auth#call` with `PATH_INFO` compatible with the core `Router` (same idea as `BetterAuth::Rails::MountedApp#mounted_path_info`). Registration rejects mount paths that normalize to `/`. `Migration.applied_migrations` only treats errors that clearly mean “schema migrations table not yet present” as empty; real failures propagate. `statements` uses a pragmatic splitter (newlines + single-line multi-statements). Extension warns on second `better_auth`. Helpers optionally emit JSON 401. Changes stay primarily in `packages/better_auth-sinatra`.

**Tech Stack:** Ruby 3.2+, Sinatra 3+, RSpec, `better_auth` core, `rake`; optional `pg` / `sqlite3` / `mysql2` in tests when mirroring real driver exceptions.

---

## Excluded (and why)

| Finding | Reason |
|--------|--------|
| Bearer / JWT on custom Sinatra routes via helpers | `Session.find_current` is cookie-centric; Bearer runs in API `before` hooks. Parity needs shared “resolve session from Rack env” in core, not only Sinatra. |
| **CSRF / `Rack::Protection`** | Framework and app policy; document same-site cookies / `Rack::Protection` in README if needed. |
| Rails `OptionBuilder` block DSL / `ControllerHelpers` | Large surface or belongs in `better_auth-rails`; Sinatra supports hash-based config. |
| **`better_auth:routes` enumerating every endpoint** | Needs stable introspection on `BetterAuth::Auth`/`Router`; this plan only improves task output + README pointer. |
| Full lexer / parser for SQL splitting | High cost; pragmatic splitter + docs. |
| Extract shared `MountedApp` to core gem | Defer until behavior is stable and tested; two implementations can match first. |
| Transactional DDL wrappers | Postgres/MySQL often auto-commit DDL; document limitation. |

---

## File map

| File | Responsibility |
|------|----------------|
| `packages/better_auth-sinatra/lib/better_auth/sinatra/mounted_app.rb` | Rack middleware: dispatch + `PATH_INFO` merge for auth |
| `packages/better_auth-sinatra/lib/better_auth/sinatra/extension.rb` | Reject `at:` → `/`; warn on duplicate `better_auth` |
| `packages/better_auth-sinatra/lib/better_auth/sinatra/configuration.rb` | `:secrets` in `AUTH_OPTION_NAMES` |
| `packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb` | `applied_migrations` rescue; `statements` splitter |
| `packages/better_auth-sinatra/lib/better_auth/sinatra/helpers.rb` | JSON-aware `require_authentication` |
| `packages/better_auth-sinatra/lib/better_auth/sinatra/tasks.rb` | Remove duplicate `generate:migration` alias; clarify `better_auth:routes` output |
| `packages/better_auth-sinatra/README.md` | Mount path, `SCRIPT_NAME`/URLMap, SQL conventions, helpers vs API, DDL |
| `packages/better_auth-sinatra/CHANGELOG.md` | User-facing notes |
| `spec/better_auth/sinatra/extension_spec.rb` | Mount behavior, root rejection, duplicate warning, JSON 401 |
| `spec/better_auth/sinatra/migration_spec.rb` | `applied_migrations`, `statements` |
| `spec/better_auth/sinatra/configuration_spec.rb` | `secrets` in `to_auth_options` |

---

### Task 1: MountedApp — logical path dispatch + Rails-compatible `PATH_INFO` forward

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/mounted_app.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Write the failing tests**

Add two examples covering both common Rack mount patterns:

**A. App mounted at the same path as auth** (Rails-engine style — `SCRIPT_NAME` carries the mount prefix):

```ruby
it "dispatches auth when SCRIPT_NAME and PATH_INFO split the mount prefix" do
  self.app = build_app(mount_path: "/api/auth")

  get "/ok", {}, {"SCRIPT_NAME" => "/api/auth", "PATH_INFO" => "/ok"}

  expect(last_response.status).to eq(200)
  expect(JSON.parse(last_response.body)).to eq("ok" => true)
end
```

**B. App mounted at a parent path** (natural Sinatra nested mount — `PATH_INFO` is already relative to the app):

```ruby
it "dispatches auth when the Sinatra app is nested under a parent Rack mount" do
  self.app = build_app(mount_path: "/auth")

  get "/auth/ok", {}, {"SCRIPT_NAME" => "/api", "PATH_INFO" => "/auth/ok"}

  expect(last_response.status).to eq(200)
  expect(JSON.parse(last_response.body)).to eq("ok" => true)
end
```

Use the same `build_app` as existing specs; `Rack::Test` merges extra env keys via the third argument to `get`.

- [x] **Step 2: Run tests to verify they fail**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec rspec spec/better_auth/sinatra/extension_spec.rb -e "SCRIPT_NAME"
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec rspec spec/better_auth/sinatra/extension_spec.rb -e "nested"
```

Expected: FAIL (404 or wrong body) because current code only checks `PATH_INFO`.

- [x] **Step 3: Implement `MountedApp`**

Replace the body of `mounted_app.rb` with behavior equivalent to the following (adjust style to match repo StandardRB). Key points:

- `mount_matches?` checks **both** `PATH_INFO` (relative to the Sinatra app) and the full logical path (`SCRIPT_NAME + PATH_INFO`). This supports both natural Sinatra nested mounts and Rails-engine-style mounts where the app itself sits at the auth prefix.
- `mounted_path_info` returns `PATH_INFO` unchanged when it already contains `@mount_path`; otherwise it reconstructs the full logical path using `SCRIPT_NAME` so the core `Router` can strip `base_path` correctly.
- Defense-in-depth: `mount_matches?` explicitly rejects `@mount_path == "/"` even though Task 2 forbids it at registration time.

```ruby
# frozen_string_literal: true

module BetterAuth
  module Sinatra
    class MountedApp
      def initialize(app, auth, mount_path:)
        @app = app
        @auth = auth
        @mount_path = normalize_path(mount_path)
      end

      def call(env)
        return @app.call(env) unless mount_matches?(env)

        merged = env.merge("PATH_INFO" => mounted_path_info(env))
        auth_rack.call(merged)
      end

      private

      def auth_rack
        @auth.respond_to?(:call) && !@auth.respond_to?(:context) ? @auth.call : @auth
      end

      def mount_matches?(env)
        return false if @mount_path == "/"

        path_info = normalize_path(env["PATH_INFO"])
        return true if path_info == @mount_path || path_info.start_with?("#{@mount_path}/")

        full = full_request_path(env)
        full == @mount_path || full.start_with?("#{@mount_path}/")
      end

      def full_request_path(env)
        script = env.fetch("SCRIPT_NAME", "").to_s
        path = env.fetch("PATH_INFO", "").to_s
        normalize_path("#{script}#{path}")
      end

      def mounted_path_info(env)
        path_info = normalize_path(env["PATH_INFO"])

        # If PATH_INFO already contains the mount path, pass it through unchanged
        # (natural Sinatra nested mount: app at /api, auth at /auth, PATH_INFO is /auth/ok)
        return path_info if path_info == @mount_path || path_info.start_with?("#{@mount_path}/")

        # Otherwise reconstruct the full logical path using SCRIPT_NAME
        # (Rails-engine style: app mounted at /api/auth, PATH_INFO is /ok)
        script_name = normalize_path(env["SCRIPT_NAME"])
        prefix = (script_name == "/") ? @mount_path : script_name

        return path_info if path_info == prefix || path_info.start_with?("#{prefix}/")

        normalize_path("#{prefix}/#{path_info.delete_prefix("/")}")
      end

      def normalize_path(path)
        normalized = path.to_s
        normalized = "/#{normalized}" unless normalized.start_with?("/")
        normalized = normalized.squeeze("/")
        normalized = normalized.delete_suffix("/") unless normalized == "/"
        normalized.empty? ? "/" : normalized
      end
    end
  end
end
```

- [x] **Step 4: Run tests**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec rspec spec/better_auth/sinatra/extension_spec.rb
```

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/mounted_app.rb packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb
git commit -m "fix(sinatra): align MountedApp with SCRIPT_NAME and PATH_INFO splits"
```

---

### Task 2: Extension — reject mount path `/`

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/extension.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Write the failing test**

```ruby
it "raises when better_auth mount path is root" do
  expect {
    Class.new(Sinatra::Base) do
      register BetterAuth::Sinatra
      set :environment, :test
      better_auth at: "/" do |config|
        config.secret = "sinatra-secret-that-is-long-enough-for-validation"
        config.base_url = "http://example.org"
        config.database = :memory
      end
    end
  }.to raise_error(ArgumentError, /mount path|better_auth.*mount/i)
end
```

Tune the regex to the final message.

- [x] **Step 2: Run test — expect FAIL**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec rspec spec/better_auth/sinatra/extension_spec.rb -e "root"
```

- [x] **Step 3: Implement**

After `mount_path = normalize_better_auth_mount_path(at)`:

```ruby
if mount_path == "/"
  raise ArgumentError,
        "better_auth mount path cannot be '/' (it would capture every request). " \
        "Use a prefix such as #{BetterAuth::Configuration::DEFAULT_BASE_PATH.inspect}."
end
```

- [x] **Step 4: Run full extension spec file**

```bash
bundle exec rspec spec/better_auth/sinatra/extension_spec.rb
```

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/extension.rb packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb
git commit -m "fix(sinatra): reject better_auth mount at root path"
```

---

### Task 3: Migration — narrow `applied_migrations` rescue

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/migration_spec.rb`

- [x] **Step 1: Write the failing test**

Expect `migrate` to **raise** when listing applied migrations fails for a non–missing-table reason (e.g. `RuntimeError` / `StandardError` with `"permission denied"` or `"connection refused"` on the SELECT). Extend the fake connection accordingly; keep happy path for CREATE used by `ensure_schema_migrations!`.

- [x] **Step 2: Run test — expect FAIL** (current bare `rescue` may return `[]` and proceed)

- [x] **Step 3: Implement**

Prefer pattern-based detection for “migrations table missing” vs real failures. Replace bare `rescue` with:

```ruby
MISSING_MIGRATIONS_TABLE_MESSAGES = [
  /no such table/i,                          # SQLite3
  /relation .* does not exist/i,             # PostgreSQL
  /table .* doesn't exist/i,                 # MySQL
  /undefined table/i,                        # PostgreSQL (PG::UndefinedTable)
  /invalid object name/i                     # MSSQL
].freeze

def applied_migrations(connection, dialect)
  rows = execute_sql(connection, "SELECT #{quote("version", dialect)} FROM #{quote("better_auth_schema_migrations", dialect)};")
  Array(rows).map { |row| row["version"] || row[:version] }
rescue UnsupportedAdapterError
  raise
rescue StandardError => error
  raise error unless missing_schema_migrations_table?(error)

  []
end

private

def missing_schema_migrations_table?(error)
  message = error.message.to_s
  MISSING_MIGRATIONS_TABLE_MESSAGES.any? { |pattern| message.match?(pattern) }
end
```

Keep `missing_schema_migrations_table?` private; match existing module style. Optionally narrow further with driver-specific exception classes (`PG::UndefinedTable`, `SQLite3::SQLException`, `Mysql2::Error`) in tests where the relevant gem is present.

- [x] **Step 4: Run migration specs**

```bash
bundle exec rspec spec/better_auth/sinatra/migration_spec.rb
```

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb packages/better_auth-sinatra/spec/better_auth/sinatra/migration_spec.rb
git commit -m "fix(sinatra): fail fast when migration bookkeeping query errors"
```

---

### Task 4: Migration — split SQL statements more reliably

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb` (`statements`)
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/migration_spec.rb`

- [x] **Step 1: Write failing test**

Cover newline-separated statements and single-line multi-statements, e.g.:

```ruby
it "splits multiple statements on one line" do
  sql = "CREATE TABLE users (id text PRIMARY KEY); CREATE INDEX idx ON users (id);"
  stmts = described_class.send(:statements, sql)
  expect(stmts.length).to eq(2)
  expect(stmts.first).to include("CREATE TABLE users")
  expect(stmts.last).to include("CREATE INDEX")
end
```

- [x] **Step 2: Implement `statements`** (pragmatic approach)

```ruby
def statements(sql)
  normalized = sql.to_s.gsub(/\r\n/, "\n").strip
  return [] if normalized.empty?

  chunks = normalized.split(/;\s*\n/)
  chunks.flat_map do |chunk|
    chunk = chunk.strip
    next [] if chunk.empty?

    if chunk.include?(";") && !chunk.include?("\n")
      chunk.split(";").map(&:strip).reject(&:empty?)
    else
      [chunk]
    end
  end
end
```

- [x] **Step 3: Run migration specs**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb packages/better_auth-sinatra/spec/better_auth/sinatra/migration_spec.rb
git commit -m "fix(sinatra): split SQL migration files more reliably"
```

---

### Task 5: Configuration — pass through `secrets`

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/configuration.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/configuration_spec.rb`

- [x] **Step 1: Failing test**

```ruby
it "includes secrets in auth options when set" do
  described_class.configure do |config|
    config.secret = secret
    config.database = :memory
    config.secrets = ["rotate-me-12345678901234567890123456789012"]
  end

  options = described_class.configuration.to_auth_options
  expect(options[:secrets]).to eq(["rotate-me-12345678901234567890123456789012"])
end
```

- [x] **Step 2: Add `:secrets` to `AUTH_OPTION_NAMES`** (alphabetically near `:secret`)

- [x] **Step 3: Run configuration specs**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/configuration.rb packages/better_auth-sinatra/spec/better_auth/sinatra/configuration_spec.rb
git commit -m "feat(sinatra): expose secrets on Sinatra configuration"
```

---

### Task 6: Warn when `better_auth` is registered twice

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/extension.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Test**

```ruby
it "warns when better_auth is configured twice on the same app class" do
  secret = "sinatra-secret-that-is-long-enough-for-validation"
  expect {
    Class.new(Sinatra::Base) do
      register BetterAuth::Sinatra
      set :environment, :test
      better_auth at: "/api/auth" do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
      end
      better_auth at: "/auth2" do |config|
        config.secret = secret
        config.base_url = "http://example.org"
        config.database = :memory
      end
    end
  }.to output(/better_auth/).to_stderr
end
```

- [x] **Step 2: At start of `better_auth`**, warn if auth already configured (use `[better_auth-sinatra]` prefix for grep).

- [ ] **Step 3: Commit**

```bash
git commit -m "chore(sinatra): warn when better_auth is registered twice"
```

---

### Task 7: JSON-friendly `require_authentication`

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/helpers.rb`
- Test: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Tests** — route with `content_type :json` + `require_authentication`; assert 401 with JSON body matching core (`BetterAuth::APIError.new("UNAUTHORIZED").to_h`) when `Accept` prefers JSON; assert non-JSON clients still get empty body (or match current behavior).

- [x] **Step 2: Implement** — if not authenticated and the request prefers JSON (use `request.preferred_type(["application/json", "text/html"]) == "application/json"` or fall back to checking `HTTP_ACCEPT` for the exact substring `application/json`), `halt 401`, `{"content-type" => "application/json"}` with `JSON.generate(BetterAuth::APIError.new("UNAUTHORIZED").to_h)`; else existing halt behavior.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(sinatra): JSON 401 for require_authentication when Accept is JSON"
```

---

### Task 8: Rake — duplicate task removal + clearer `better_auth:routes` output

**Files:**

- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/tasks.rb`

- [x] **Step 1:** Remove the redundant top-level `task "generate:migration"` that only delegates to the namespaced task (keep `namespace :generate` → `task :migration`).
  > **Note:** This is a breaking change for anyone currently running `rake generate:migration`. Document the removal in CHANGELOG and README; users should switch to `rake better_auth:generate:migration`.

- [x] **Step 2:** Update `better_auth:routes` to print a short message: mounted path / handler hint + pointer to core HTTP API / OpenAPI in docs (keep lines &lt; 120 chars).

- [x] **Step 3:** Run specs that load tasks (e.g. migration spec install examples).

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-sinatra/lib/better_auth/sinatra/tasks.rb
git commit -m "chore(sinatra): rake cleanup and clearer routes task output"
```

---

### Task 9: README + CHANGELOG

**Files:**

- `packages/better_auth-sinatra/README.md`
- `packages/better_auth-sinatra/CHANGELOG.md`

- [x] **README** — Add or extend sections:

  1. **Mount path:** Cannot be `/`. `better_auth at:` defines the path prefix that the core router uses for matching. The adapter supports two common Rack mount patterns:
     - **Natural Sinatra nested mount:** your app sits under a `Rack::URLMap` (e.g. at `/api`) and you configure `at: "/auth"`. Auth routes are then available at `/api/auth/*`. The middleware matches using `PATH_INFO` as seen by the Sinatra app.
     - **Rails-engine style mount:** your Sinatra app itself is mounted at the same path as auth (e.g. app at `/api/auth`, configured `at: "/api/auth"`). The middleware reconstructs the full logical path from `SCRIPT_NAME` + `PATH_INFO` so the core router can strip `base_path` correctly.
  2. **Reverse proxies / `Rack::URLMap`:** document that `PATH_INFO` seen by the app must align with the configured prefix where relevant.
  3. **SQL migrations:** prefer one statement per line ending with `;`; hand-edited SQL with semicolons inside literals may confuse the splitter; DDL may not roll back—back up before migrate.
  4. **Helpers vs API auth:** custom routes use cookie-centric session resolution; Bearer-heavy clients may need API routes or app extensions.

- [x] **CHANGELOG** — Under Unreleased: bullets for MountedApp fix, `/` rejection, migration behavior, `secrets`, SQL splitting, duplicate warning, JSON 401, rake/docs.

- [ ] **Commit**

```bash
git add packages/better_auth-sinatra/README.md packages/better_auth-sinatra/CHANGELOG.md
git commit -m "docs(sinatra): README and changelog for Sinatra hardening"
```

---

### Task 10: Package regression suite + Standard

- [x] **Step 1:**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec rspec
```

- [x] **Step 2:**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-sinatra && bundle exec standardrb
```

Fix violations; commit lint-only fixes if needed.

---

## Self-review

| Requirement | Task |
|-------------|------|
| Nested Rack `SCRIPT_NAME`/`PATH_INFO` | Task 1 |
| `/` mount footgun | Task 2 |
| Swallowed DB errors in `applied_migrations` | Task 3 |
| SQL statement splitting | Task 4 |
| Core `secrets` parity | Task 5 |
| Duplicate `better_auth` | Task 6 |
| JSON 401 for helpers | Task 7 |
| Rake duplicate + routes message | Task 8 |
| User-facing docs | Task 9 |
| Full suite + lint | Task 10 |
| Bearer/helpers parity in core | Excluded |
| Full SQL lexer | Excluded |

**Consistency:** Mirror `ArgumentError` text in README; verify JSON error shape against core before merging Task 7. Verify both `PATH_INFO`-relative and `SCRIPT_NAME`-reconstruction mount patterns in Task 1 tests before considering Task 1 complete.

---

## Execution handoff

Merged plan: `.docs/plans/2026-05-03-1430--sinatra-hardening.md` (replaces `…--sinatra-integration-hardening.md` and `…--sinatra-adapter-hardening.md`).

**Options:**

1. **Subagent-driven (recommended)** — `superpowers:subagent-driven-development`
2. **Inline execution** — `superpowers:executing-plans`
