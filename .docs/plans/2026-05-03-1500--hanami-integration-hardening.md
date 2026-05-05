# Hanami integration hardening — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply fixes for confirmed gaps in `better_auth-hanami` (helpers, adapters, generators, docs) without expanding scope into core-gem behavior or client-owned infrastructure.

**Architecture:** Changes stay inside `packages/better_auth-hanami/` except where noted. Session resolution in actions will match Sinatra by calling `Context#prepare_for_request!` when present. Database fallback will emit an explicit warning. Generators become safer (deduped requires, clearer failure modes, optional migration overwrite). README will align with generated artifacts and document Rack/CORS expectations.

**Tech stack:** Ruby 3.x, RSpec, Hanami 2.x patterns, `better_auth` core as dependency.

## Execution notes

- [x] Compared the proposed `prepare_for_request!` behavior with upstream Better Auth request context handling and the Ruby Sinatra adapter; implementing the Hanami helper call matches both.
- [x] Kept `MountedApp` as documentation-only because existing Hanami routing specs already cover the expected `PATH_INFO` contract and changing SCRIPT_NAME behavior would be riskier without a failing custom Rack reproduction.
- [x] Implemented Tasks 1-6 with focused specs. Task 5's original strict-substring concern was partially already handled by current code, but the regex adaptation is still useful for flexible whitespace and now inserts before blank-line body content.
- [x] Skipped Task 7 because the README documents the Ruby API for `force: true`, not a new rake task.

**Scope exclusions (why not in this plan):**


| Item                                                                     | Reason                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Explicit `trusted_origins: []` (“deny all”)**                          | Core `BetterAuth::Configuration#normalize_trusted_origins` merges env/dynamic defaults; expressing strict empty list needs a **core** API change, not a Hanami-only merge fix.                                                               |
| **Automatic CORS middleware in the gem**                                 | `Access-Control-`* policy (paths, credentials, origins) is **application** middleware; we only document the expectation.                                                                                                                     |
| **Changing `MountedApp` to mirror Rails `SCRIPT_NAME` logic by default** | Current Hanami routing specs pass with `Hanami::Slice::Router`; altering prefix logic without a **failing integration reproduction** risks regressions. We document differences for custom Rack stacks instead of changing behavior blindly. |
| **Relation generator overwrite / inflector**                             | Overwriting user-edited relations is destructive; irregular plurals need a shared inflector contract. Out of scope unless product asks; README already hints at manual steps.                                                                |


---

## File map


| File                                                                                   | Role                                                                        |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| `packages/better_auth-hanami/lib/better_auth/hanami/action_helpers.rb`                 | Add `prepare_for_request!` before building endpoint context.                |
| `packages/better_auth-hanami/spec/better_auth/hanami/action_helpers_spec.rb`           | New examples for `prepare_for_request!` and optional dynamic URL behavior.  |
| `packages/better_auth-hanami/lib/better_auth/hanami/sequel_adapter.rb`                 | Warn when falling back to Memory from container resolution.                 |
| `packages/better_auth-hanami/spec/better_auth/hanami/sequel_adapter_spec.rb`           | Examples for `from_container`, warning, and `safe_fetch`.                   |
| `packages/better_auth-hanami/lib/better_auth/hanami/generators/migration_generator.rb` | Add `force:` to overwrite migration when requested.                         |
| `packages/better_auth-hanami/lib/better_auth/hanami/generators/install_generator.rb`   | Dedupe requires; explicit outcome when `routes.rb` / `settings.rb` missing. |
| `packages/better_auth-hanami/spec/generators/better_auth/hanami/`*                     | Cover new generator behavior.                                               |
| `packages/better_auth-hanami/lib/better_auth/hanami/mounted_app.rb`                    | Class-level documentation only (no logic change in this plan).              |
| `packages/better_auth-hanami/README.md`                                                | trusted_origins, CORS, regeneration, Rack notes.                            |


---

### Task 1: `prepare_for_request!` in `ActionHelpers`

**Files:**

- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/action_helpers.rb`
- Test: `packages/better_auth-hanami/spec/better_auth/hanami/action_helpers_spec.rb`
- **Step 1: Write the failing test**

Add an example that proves `prepare_for_request!` runs before session resolution when the context responds to it. Use the existing `BetterAuthHanamiAction` and a real configured `BetterAuth::Hanami.auth` (same pattern as “resolves and caches session data”).

```ruby
it "prepares auth context for the request before resolving session" do
  BetterAuth::Hanami.configure do |config|
    config.secret = secret
    config.database = :memory
    config.base_url = "http://localhost:2300"
    config.email_and_password = {enabled: true}
  end

  auth = BetterAuth::Hanami.auth
  prepared = false
  allow(auth.context).to receive(:prepare_for_request!).and_wrap_original do |m, req|
    prepared = true
    m.call(req)
  end

  signup_headers = sign_up_headers
  request = fake_request({}, cookie: cookie_header(signup_headers.fetch("set-cookie")))
  action.current_user(request)

  expect(prepared).to be(true)
end
```

If `prepare_for_request!` is not invoked yet, this test **fails** with `prepared` still false.

- **Step 2: Run test to verify it fails**

Run:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-hanami
bundle exec rspec spec/better_auth/hanami/action_helpers_spec.rb -e "prepares auth context"
```

Expected: **FAIL** (`prepared` is false).

- **Step 3: Minimal implementation**

In `resolve_better_auth_session`, introduce a local `auth` variable so `prepare_for_request!` can be called before the endpoint context is built:

```ruby
def resolve_better_auth_session(request)
  auth = BetterAuth::Hanami.auth
  auth.context.prepare_for_request!(request) if auth.context.respond_to?(:prepare_for_request!)

  context = BetterAuth::Endpoint::Context.new(
    path: request_path(request),
    method: request_method(request),
    query: request_params(request),
    body: {},
    params: {},
    headers: {"cookie" => request_cookie(request)},
    context: auth.context,
    request: request
  )
  BetterAuth::Session.find_current(context, disable_refresh: true)
end
```

- **Step 4: Run tests**

```bash
bundle exec rspec spec/better_auth/hanami/action_helpers_spec.rb
```

Expected: **PASS** for the whole file.

- **Step 5: Commit**

```bash
git add packages/better_auth-hanami/lib/better_auth/hanami/action_helpers.rb \
        packages/better_auth-hanami/spec/better_auth/hanami/action_helpers_spec.rb
git commit -m "fix(hanami): prepare auth context in action helpers before session lookup"
```

---

### Task 2: Warn on silent Memory fallback in `SequelAdapter`

**Files:**

- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/sequel_adapter.rb`
- Test: `packages/better_auth-hanami/spec/better_auth/hanami/sequel_adapter_spec.rb`
- **Step 1: Write the failing test**

At the end of `sequel_adapter_spec.rb`, add a context that triggers `from_container` with a container lacking `db.gateway` and expects `Kernel.warn` (or a test stub) once.

```ruby
describe ".from_container" do
  it "warns when falling back to memory adapter" do
    container = Class.new do
      def key?(_key) = false

      def [](_key)
        raise KeyError
      end
    end.new

    expect(Kernel).to receive(:warn).with(/in-memory|Memory/i)

    described_class.from_container(container, {secret: "x" * 32})
  end
end
```

Adjust the warning regex to match the final message. Run before implementation — the example may **fail** because `warn` is not called yet, or because return type differs (ensure expectation matches `Memory` adapter instance).

- **Step 2: Run test to verify it fails**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-hanami
bundle exec rspec spec/better_auth/hanami/sequel_adapter_spec.rb -e "warns when falling back"
```

Expected: **FAIL** (no warning).

- **Step 3: Implementation**

In **both** `from_hanami` (when `container` is nil) and `from_container` (when `gateway` is nil), immediately before `return BetterAuth::Adapters::Memory.new(options)`, call:

```ruby
Kernel.warn(
  "[better_auth-hanami] SequelAdapter: using BetterAuth::Adapters::Memory " \
  "(no Hanami container or db.gateway). Persisted auth data will not survive process restart."
)
```

Optional: skip warning when `ENV["BETTER_AUTH_SILENCE_MEMORY_WARNING"] == "1"` for CI noise control — only add if tests need it.

- **Step 4: Run tests**

```bash
bundle exec rspec spec/better_auth/hanami/sequel_adapter_spec.rb
```

Expected: **PASS**.

- **Step 5: Commit**

```bash
git add packages/better_auth-hanami/lib/better_auth/hanami/sequel_adapter.rb \
        packages/better_auth-hanami/spec/better_auth/hanami/sequel_adapter_spec.rb
git commit -m "feat(hanami): warn when Sequel adapter falls back to memory"
```

---

### Task 3: `MigrationGenerator` supports `force: true`

**Files:**

- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/generators/migration_generator.rb`
- Test: `packages/better_auth-hanami/spec/generators/better_auth/hanami/migration_generator_spec.rb`
- **Step 1: Write the failing test**

Extend the migration generator spec: create a temp dir with an existing `*_create_better_auth_tables.rb`, call `run(force: true)`, expect a **new** migration written (or same path overwritten — choose one behavior and assert file mtime or content contains updated timestamp comment if you add one). Minimal approach: assert `File.read(path)` includes table names after force regeneration.

Example skeleton:

```ruby
it "overwrites migration when force: true" do
  Dir.mktmpdir do |dir|
    migrate_dir = File.join(dir, "config/db/migrate")
    FileUtils.mkdir_p(migrate_dir)
    path = File.join(migrate_dir, "20200101000000_create_better_auth_tables.rb")
    File.write(path, "# old")

    generator = described_class.new(destination_root: dir)
    generator.run(force: true)

    content = File.read(path)
    expect(content).not_to eq("# old")
    expect(content).to include("create_table")
  end
end
```

Run before `run` accepts `force:` — test should **fail** with ArgumentError.

- **Step 2: Run failing test**

```bash
bundle exec rspec spec/generators/better_auth/hanami/migration_generator_spec.rb -e "overwrites migration"
```

Expected: **FAIL** (ArgumentError for unknown keyword, or old content preserved).

- **Step 3: Implementation**

```ruby
def initialize(destination_root: Dir.pwd, configuration: nil, force: false)
  @destination_root = destination_root
  @configuration = configuration
  @force = force
end

def run(force: nil)
  force = @force if force.nil?
  return migration_path if existing_migration? && !force
  # ... existing write logic
end
```

Ensure default `run` without kwargs keeps **previous** behavior (`force` false).

- **Step 4: Run tests**

```bash
bundle exec rspec spec/generators/better_auth/hanami/migration_generator_spec.rb
```

Expected: **PASS**.

- **Step 5: Commit**

```bash
git add packages/better_auth-hanami/lib/better_auth/hanami/generators/migration_generator.rb \
        packages/better_auth-hanami/spec/generators/better_auth/hanami/migration_generator_spec.rb
git commit -m "feat(hanami): allow forcing Better Auth migration regeneration"
```

---

### Task 4: `InstallGenerator` — dedupe requires and visible outcome when files missing

**Files:**

- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/generators/install_generator.rb`
- Test: `packages/better_auth-hanami/spec/generators/better_auth/hanami/install_generator_spec.rb`
- **Step 1: Write failing tests**

1. **Dedupe:** Build temp `config/routes.rb` that contains **both** the old routing require and the new one, e.g.:

   ```ruby
   require "better_auth/hanami/routing"
   require "better_auth/hanami"

   module Bookshelf
     class Routes < Hanami::Routes
     end
   end
   ```

   Run the generator; assert the result contains exactly **one** `require "better_auth/hanami"` line. (The generator’s `gsub` converts the old require into the new one, creating a consecutive duplicate that the current code does not collapse.)

2. **Missing routes:** With temp dir **without** `config/routes.rb`, expect a `Kernel.warn` when `run` is invoked so CI stays non-interactive:

   ```ruby
   expect(Kernel).to receive(:warn).with(/routes\.rb/)
   ```

   Use the same `receive(:warn)` style for the missing-settings test.

- **Step 2: Run failing tests**

Expected: **FAIL**.

- **Step 3: Implementation**

After writing `config/routes.rb` content in `update_routes`, normalize duplicate requires:

```ruby
def dedupe_better_auth_requires(content)
  lines = content.lines
  out = []
  prev = nil
  lines.each do |line|
    next if line.strip == prev && line.include?("better_auth/hanami")

    out << line
    prev = line.strip
  end
  out.join
end
```

Refine so only **identical consecutive** `require "better_auth/hanami"` lines collapse.

At start of `update_routes` / `update_settings`, if file missing:

```ruby
Kernel.warn("[better_auth-hanami] InstallGenerator: #{path} not found; skipping routes wiring. Add Hanami routes manually.")
```

Same pattern for settings.

- **Step 4: Run tests**

```bash
bundle exec rspec spec/generators/better_auth/hanami/install_generator_spec.rb
```

Expected: **PASS**.

- **Step 5: Commit**

```bash
git add packages/better_auth-hanami/lib/better_auth/hanami/generators/install_generator.rb \
        packages/better_auth-hanami/spec/generators/better_auth/hanami/install_generator_spec.rb
git commit -m "fix(hanami): harden install generator requires and missing-file warnings"
```

---

### Task 5: Safer `settings.rb` injection

**Files:**

- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/generators/install_generator.rb`
- Test: `packages/better_auth-hanami/spec/generators/better_auth/hanami/install_generator_spec.rb`
- **Step 1: Write failing test**

Create temp `config/settings.rb` with extra blank line after `class Settings < Hanami::Settings`:

```ruby
class Settings < Hanami::Settings

  setting :foo, default: 1
end
```

Run `update_settings`; expect `better_auth_secret` inserted **after** the class line.

- **Step 2: Run test**

Expected: **FAIL** if current substring match is too strict.

- **Step 3: Implementation**

Replace single `sub` with regex:

```ruby
content = content.sub(
  /(class\s+Settings\s*<\s*Hanami::Settings\s*\n)/,
  "\\1    setting :better_auth_secret, constructor: Types::String.constrained(min_size: 32)\n" \
  "    setting :better_auth_url, constructor: Types::String.optional\n"
)
```

Keep `return if content.include?("setting :better_auth_secret")` guard.

- **Step 4: Run tests**

```bash
bundle exec rspec spec/generators/better_auth/hanami/install_generator_spec.rb
```

- **Step 5: Commit**

```bash
git add packages/better_auth-hanami/lib/better_auth/hanami/generators/install_generator.rb \
        packages/better_auth-hanami/spec/generators/better_auth/hanami/install_generator_spec.rb
git commit -m "fix(hanami): relax settings injection pattern for install generator"
```

---

### Task 6: Documentation — `README.md` + `MountedApp` class comment

**Files:**

- Modify: `packages/better_auth-hanami/README.md`
- Modify: `packages/better_auth-hanami/lib/better_auth/hanami/mounted_app.rb` (comment only)
- **Step 1: README additions**

In **Configuration** section, mirror generated provider:

- Show `config.trusted_origins = [settings.better_auth_url].compact` (or equivalent) next to other options.

Add short **CORS** subsection: origin validation uses `trusted_origins`; browser preflight needs separate Rack middleware for `Access-Control-`* headers.

Add **Regenerating migrations** subsection: explain `MigrationGenerator.new(...).run(force: true)` or rake task wiring if you expose it in `lib/tasks/better_auth.rake` (if you add a rake task, implement in same commit; otherwise document Ruby API).

Add **Rack mount** note: `MountedApp` expects `PATH_INFO` as Hanami’s router supplies (see `spec/better_auth/hanami/routing_spec.rb`); embedding in a **custom** Rack stack with different `SCRIPT_NAME` conventions may need app-level adjustments — compare with `better_auth-rails` `MountedApp` if debugging path issues.

- **Step 2: `MountedApp` comment**

Above `class MountedApp`, add:

```ruby
# Rewrites PATH_INFO so the core router sees paths under +mount_path+.
# Hanami's +Slice::Router+ passes PATH_INFO as exercised in routing specs; custom
# Rack mounts that differ from that contract may need different rewriting (see Rails adapter).
```

- **Step 3: Proofread**

No placeholder sections; link to internal spec path as plain text.

- **Step 4: Commit**

```bash
git add packages/better_auth-hanami/README.md \
        packages/better_auth-hanami/lib/better_auth/hanami/mounted_app.rb
git commit -m "docs(hanami): align README with provider and document Rack/CORS caveats"
```

---

### Task 7: Optional rake task for forced migration (only if README promises it)

**Condition:** If Task 6 README documents a rake task for `force`, implement it; otherwise skip this task entirely.

**Files:**

- Modify: `packages/better_auth-hanami/lib/tasks/better_auth.rake`
- Test: add lightweight spec or invoke in generator spec — prefer documenting Ruby API only to minimize scope.
- **Step 1:** If skipping, delete any README mention of rake `force` from Task 6 edits.

---

## Self-review


| Spec / gap                                            | Task covering it       |
| ----------------------------------------------------- | ---------------------- |
| `prepare_for_request!` missing in helpers             | Task 1                 |
| Silent Memory adapter                                 | Task 2                 |
| Migration regeneration blocked by glob                | Task 3 + README Task 6 |
| Duplicate requires / missing files                    | Task 4                 |
| Brittle settings insert                               | Task 5                 |
| README vs provider / CORS / Rack                      | Task 6                 |
| MountedApp behavior clarity without risky code change | Task 6 comment         |


**Placeholder scan:** None intentional — Task 7 is conditional and references concrete condition.

**Signature consistency:** `MigrationGenerator#run(force: nil)` defers to `@force`; tests must match implemented API.

---

## Execution handoff

Plan saved to `.docs/plans/2026-05-03-1500--hanami-integration-hardening.md`.

**1. Subagent-driven (recommended)** — Dispatch a fresh subagent per task; review between tasks.

**2. Inline execution** — Run tasks in one session with `superpowers:executing-plans` checkpoints.

Which approach do you want?
