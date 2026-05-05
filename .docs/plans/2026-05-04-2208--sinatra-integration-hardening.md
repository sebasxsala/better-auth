# Sinatra Integration Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Harden `better_auth-sinatra` so Sinatra helpers and mounts preserve Better Auth core behavior more closely and migration tasks are safer for realistic SQL.

**Architecture:** Keep authentication behavior in `packages/better_auth`; change only the Sinatra integration layer, tests, docs, and example app. Use the core `auth.api.get_session` path for helper session lookup so plugin hooks and response headers behave like upstream server integrations.

**Tech Stack:** Ruby 3.2+, Sinatra, Rack, RSpec, StandardRB, Better Auth Ruby core, upstream Better Auth v1.6.9.

---

## Analysis Summary

- [x] Read root `AGENTS.md` and `packages/better_auth-sinatra/AGENTS.md`.
- [x] Confirmed upstream submodule is present at `@better-auth/api-key@1.6.9`.
- [x] Reviewed upstream `upstream/packages/better-auth/src/integrations/node.ts` and `upstream/packages/better-auth/src/integrations/next-js.ts`.
- [x] Reviewed Sinatra adapter files under `packages/better_auth-sinatra/lib/better_auth/sinatra/`.
- [x] Reviewed Sinatra package specs under `packages/better_auth-sinatra/spec/`.
- [x] Compared against Ruby core `BetterAuth::Router`, `BetterAuth::API`, `BetterAuth::Session`, cookies, and Rails helper patterns.
- [x] Ran current Sinatra specs: `rbenv exec bundle exec rspec` from `packages/better_auth-sinatra`, 28 examples, 0 failures.

## Findings

1. `packages/better_auth-sinatra/lib/better_auth/sinatra/helpers.rb` resolves helpers with `BetterAuth::Session.find_current` directly. That bypasses `auth.api.get_session`, so plugin before/after hooks such as the bearer plugin are skipped and Better Auth response headers from session lookup are not applied to the Sinatra response. Upstream Next integration explicitly bridges session response cookies outside router requests.
2. `helpers.rb` passes only the `cookie` header into `Endpoint::Context`. The core API already has Rack env header extraction that preserves `authorization`, `host`, forwarded headers, content headers, and other plugin-relevant values.
3. `packages/better_auth-sinatra/lib/better_auth/sinatra/mounted_app.rb` rewrites `PATH_INFO` for the shared auth mount case but leaves `SCRIPT_NAME` unchanged. That keeps routing working, but violates the Rack invariant that `SCRIPT_NAME + PATH_INFO` is the request path. `Rack::Request#path` and `#url` can become `/api/auth/api/auth/ok`, which can affect plugins that inspect `request.url`.
4. `packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb` splits SQL with simple semicolon rules. It is documented as limited, but it currently corrupts valid SQL containing semicolons inside quoted strings, and will also mishandle PostgreSQL dollar-quoted blocks.
5. `examples/sinatra/app.rb` is still a placeholder and does not register or configure `BetterAuth::Sinatra`, so it is not a working example of this package.

---

### Task 1: Route Sinatra Helper Lookup Through Core API

**Files:**
- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/helpers.rb`
- Modify: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Add a failing bearer-helper spec**

Add an example proving a Sinatra route helper can authenticate with the Better Auth bearer plugin and no cookie header:

```ruby
it "lets Sinatra helpers resolve the current user from the bearer plugin" do
  self.app = build_app(plugins: [BetterAuth::Plugins.bearer])
  sign_up_email("ada@example.com")
  token_cookie = cookie_header(last_response["set-cookie"]).split("; ").find { |pair| pair.start_with?("better-auth.session_token=") }
  signed_token = token_cookie.split("=", 2).last

  clear_cookies
  get "/dashboard", {}, "HTTP_AUTHORIZATION" => "Bearer #{signed_token}"

  expect(last_response.status).to eq(200)
  data = JSON.parse(last_response.body)
  expect(data.fetch("authenticated")).to eq(true)
  expect(data.fetch("user").fetch("email")).to eq("ada@example.com")
end
```

Run:

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec spec/better_auth/sinatra/extension_spec.rb
```

Expected before implementation: this new example fails because `resolve_better_auth_session` only passes `cookie` headers and does not run plugin hooks.

- [x] **Step 2: Add a failing response-cookie propagation spec**

Add an example proving stale Better Auth cookies are cleared when helpers discover the session is gone:

```ruby
it "applies Better Auth response cookies emitted during helper session lookup" do
  self.app = build_app
  sign_up_email("ada@example.com")
  original_cookie = cookie_header(last_response["set-cookie"])

  post "/api/auth/sign-out", "{}", {
    "CONTENT_TYPE" => "application/json",
    "HTTP_ORIGIN" => "http://example.org",
    "HTTP_COOKIE" => original_cookie
  }
  expect(last_response.status).to eq(200)

  clear_cookies
  get "/dashboard", {}, "HTTP_COOKIE" => original_cookie

  expect(last_response.status).to eq(200)
  expect(JSON.parse(last_response.body).fetch("authenticated")).to eq(false)
  expect(last_response["set-cookie"]).to include("better-auth.session_token=")
  expect(last_response["set-cookie"].downcase).to include("max-age=0")
end
```

Expected before implementation: the helper returns unauthenticated but no clearing `Set-Cookie` header is emitted by the Sinatra response.

- [x] **Step 3: Replace direct session lookup with `auth.api.get_session`**

Change `resolve_better_auth_session` to call the core API path and keep request-local memoization in `request.env["better_auth.session"]`:

```ruby
def resolve_better_auth_session
  auth = better_auth_auth
  result = auth.api.get_session(
    headers: better_auth_request_headers,
    return_headers: true
  )
  apply_better_auth_response_headers(result[:headers] || result["headers"] || {})
  result[:response] || result["response"]
end
```

Add a private helper mirroring the core API's Rack env header normalization:

```ruby
def better_auth_request_headers
  request.env.each_with_object({}) do |(key, value), headers|
    case key
    when "CONTENT_TYPE"
      headers["content-type"] = value if value
    when "CONTENT_LENGTH"
      headers["content-length"] = value if value
    else
      next unless key.start_with?("HTTP_")

      headers[key.delete_prefix("HTTP_").downcase.tr("_", "-")] = value
    end
  end
end
```

- [x] **Step 4: Bridge Better Auth response headers onto Sinatra responses**

Apply only `Set-Cookie` from helper session lookup to avoid changing unrelated Sinatra route headers:

```ruby
def apply_better_auth_response_headers(headers)
  set_cookie = headers["set-cookie"] || headers["Set-Cookie"] || headers[:set_cookie]
  return if set_cookie.to_s.empty?

  existing = response.headers["set-cookie"].to_s
  response.headers["set-cookie"] = [existing, set_cookie.to_s].reject(&:empty?).join("\n")
end
```

Keep this helper private. Do not alter status, content type, or body headers for the Sinatra route.

- [x] **Step 5: Run the targeted helper specs**

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec spec/better_auth/sinatra/extension_spec.rb
```

Expected: all examples in `extension_spec.rb` pass, including the two new examples.

---

### Task 2: Preserve Rack Path Invariants In Shared Mounts

**Files:**
- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/mounted_app.rb`
- Modify: `packages/better_auth-sinatra/spec/better_auth/sinatra/extension_spec.rb`

- [x] **Step 1: Add a failing request URL/path spec**

Add a plugin endpoint that reports Rack request path and URL when the shared auth mount pattern splits `SCRIPT_NAME` and `PATH_INFO`:

```ruby
it "does not duplicate SCRIPT_NAME in Rack request path for shared auth mounts" do
  plugin = BetterAuth::Plugin.new(
    id: "sinatra-request-url",
    endpoints: {
      request_url_probe: BetterAuth::Endpoint.new(path: "/request-url-probe", method: "GET") do |ctx|
        {
          path: ctx.request.path,
          url: ctx.request.url
        }
      end
    }
  )
  self.app = build_app(mount_path: "/api/auth", plugins: [plugin])

  get "/request-url-probe", {}, {
    "SCRIPT_NAME" => "/api/auth",
    "PATH_INFO" => "/request-url-probe",
    "HTTP_HOST" => "example.org"
  }

  expect(last_response.status).to eq(200)
  data = JSON.parse(last_response.body)
  expect(data.fetch("path")).to eq("/api/auth/request-url-probe")
  expect(data.fetch("url")).to eq("http://example.org/api/auth/request-url-probe")
end
```

Expected before implementation: Rack can report duplicated path pieces such as `/api/auth/api/auth/request-url-probe`.

- [x] **Step 2: Rewrite env consistently**

In `MountedApp#call`, build a next env and clear `SCRIPT_NAME` only when the adapter reconstructed a full `PATH_INFO` from the original split shared mount:

```ruby
def call(env)
  return @app.call(env) unless mount_matches?(env)

  rewritten_path = mounted_path_info(env)
  next_env = env.merge("PATH_INFO" => rewritten_path)
  next_env["SCRIPT_NAME"] = "" if shared_mount_rewrite?(env, rewritten_path)
  auth.call(next_env)
end
```

Add a private predicate:

```ruby
def shared_mount_rewrite?(env, rewritten_path)
  script_name = normalize_path(env["SCRIPT_NAME"])
  original_path = normalize_path(env["PATH_INFO"])
  script_name != "/" &&
    !original_path.start_with?("#{@mount_path}/") &&
    rewritten_path.start_with?("#{@mount_path}/")
end
```

Preserve the existing nested parent mount behavior where `SCRIPT_NAME="/api"` and `PATH_INFO="/auth/ok"` should remain coherent as `/api/auth/ok`.

- [x] **Step 3: Run mount specs**

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec spec/better_auth/sinatra/extension_spec.rb
```

Expected: existing mount tests and the new request URL/path test pass.

---

### Task 3: Harden SQL Migration Statement Splitting

**Files:**
- Modify: `packages/better_auth-sinatra/lib/better_auth/sinatra/migration.rb`
- Modify: `packages/better_auth-sinatra/spec/better_auth/sinatra/migration_spec.rb`

- [x] **Step 1: Add failing splitter specs for valid semicolons**

Add examples for quoted strings and PostgreSQL dollar-quoted blocks:

```ruby
it "does not split semicolons inside quoted SQL strings" do
  sql = "INSERT INTO notes (body) VALUES ('a;b');\nCREATE INDEX idx_notes_body ON notes (body);"

  expect(described_class.statements(sql)).to eq([
    "INSERT INTO notes (body) VALUES ('a;b')",
    "CREATE INDEX idx_notes_body ON notes (body)"
  ])
end

it "does not split semicolons inside PostgreSQL dollar-quoted blocks" do
  sql = <<~SQL
    DO $$
    BEGIN
      RAISE NOTICE 'a;b';
    END
    $$;
    CREATE TABLE audit_log (id text PRIMARY KEY);
  SQL

  expect(described_class.statements(sql)).to eq([
    "DO $$\nBEGIN\n  RAISE NOTICE 'a;b';\nEND\n$$",
    "CREATE TABLE audit_log (id text PRIMARY KEY)"
  ])
end
```

Expected before implementation: the quoted string example currently splits into invalid fragments.

- [x] **Step 2: Replace simple split with a small SQL scanner**

Implement `statements(sql)` as a state machine that tracks:

- single-quoted strings, including doubled single quotes
- double-quoted identifiers, including doubled double quotes
- line comments starting with `--`
- block comments delimited by `/*` and `*/`
- PostgreSQL dollar-quoted strings such as `$$...$$` and `$tag$...$tag$`

Keep the public method signature unchanged:

```ruby
def statements(sql)
  normalized = sql.to_s.gsub("\r\n", "\n").strip
  return [] if normalized.empty?

  split_sql_statements(normalized)
end
```

Add focused private helpers inside `Migration`:

```ruby
def split_sql_statements(sql)
  output = []
  buffer = +""
  index = 0
  quote = nil
  line_comment = false
  block_comment = false
  dollar_tag = nil

  while index < sql.length
    char = sql[index]
    next_char = sql[index + 1]

    if line_comment
      buffer << char
      line_comment = false if char == "\n"
      index += 1
      next
    end

    if block_comment
      buffer << char
      if char == "*" && next_char == "/"
        buffer << next_char
        block_comment = false
        index += 2
      else
        index += 1
      end
      next
    end

    if dollar_tag
      if sql[index, dollar_tag.length] == dollar_tag
        buffer << dollar_tag
        index += dollar_tag.length
        dollar_tag = nil
      else
        buffer << char
        index += 1
      end
      next
    end

    if quote
      buffer << char
      if char == quote && sql[index + 1] == quote
        buffer << sql[index + 1]
        index += 2
      elsif char == quote
        quote = nil
        index += 1
      else
        index += 1
      end
      next
    end

    if char == "-" && next_char == "-"
      buffer << char << next_char
      line_comment = true
      index += 2
      next
    end

    if char == "/" && next_char == "*"
      buffer << char << next_char
      block_comment = true
      index += 2
      next
    end

    tag = dollar_quote_tag_at(sql, index)
    if tag
      buffer << tag
      dollar_tag = tag
      index += tag.length
      next
    end

    if char == "'" || char == "\""
      buffer << char
      quote = char
      index += 1
      next
    end

    if char == ";"
      statement = buffer.strip
      output << statement unless statement.empty?
      buffer.clear
      index += 1
      next
    end

    buffer << char
    index += 1
  end

  tail = buffer.strip
  output << tail unless tail.empty?
  output
end

def dollar_quote_tag_at(sql, index)
  match = sql[index..]&.match(/\A\$[A-Za-z_][A-Za-z0-9_]*\$|\A\$\$/)
  match&.[](0)
end
```

The scanner should append a statement only when it sees a semicolon outside every quoted/comment state. Strip a trailing semicolon from each emitted statement and reject empty statements.

- [x] **Step 3: Run migration specs**

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec spec/better_auth/sinatra/migration_spec.rb
```

Expected: migration specs pass, including quoted-string and dollar-quote coverage.

---

### Task 4: Make The Sinatra Example App Real

**Files:**
- Modify: `examples/sinatra/app.rb`
- Modify: `packages/better_auth-sinatra/README.md`
- Modify: `docs/content/docs/integrations/sinatra.mdx`

- [x] **Step 1: Update `examples/sinatra/app.rb` to mount the adapter**

Replace the placeholder protected route with a working in-memory demo configuration:

```ruby
class App < Sinatra::Base
  register BetterAuth::Sinatra

  set :environment, ENV.fetch("RACK_ENV", "development").to_sym

  better_auth at: "/api/auth" do |config|
    config.secret = ENV.fetch("BETTER_AUTH_SECRET", "change-me-sinatra-secret-12345678901234567890")
    config.base_url = ENV.fetch("BETTER_AUTH_URL", "http://localhost:4567")
    config.database = :memory
    config.email_and_password = {enabled: true}
  end

  get "/" do
    "Hello from Sinatra + Better Auth"
  end

  get "/protected" do
    require_authentication
    "Signed in as #{current_user.fetch("email")}"
  end
end
```

Keep the example clearly development-only by using `:memory` and environment-backed secrets.

- [x] **Step 2: Document helper parity and bearer behavior**

In both docs files, add a short helper note:

```markdown
Sinatra helpers resolve sessions through the core `get-session` API path, so Better Auth plugin hooks that affect session lookup, such as the bearer plugin, run for `current_user` and `require_authentication`.
```

Also document that helper session lookup may emit Better Auth `Set-Cookie` headers when stale cookies need to be cleared or refreshed.

- [x] **Step 3: Run docs/package checks affected by the example**

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rspec
rbenv exec bundle exec standardrb
```

Expected: package specs and StandardRB pass.

---

### Task 5: Final Verification

**Files:**
- No new files beyond the modifications above.

- [x] **Step 1: Run the full Sinatra package suite**

```bash
cd packages/better_auth-sinatra
rbenv exec bundle exec rake ci
```

Expected: StandardRB and RSpec pass.

- [x] **Step 2: Inspect the final diff**

```bash
git diff -- packages/better_auth-sinatra examples/sinatra docs/content/docs/integrations/sinatra.mdx
```

Expected: changes are limited to Sinatra integration, docs, example app, and Sinatra specs. No core auth behavior is moved into `better_auth-sinatra`.

- [x] **Step 3: Update this plan**

Mark completed steps with `[x]`. If implementation discovers a meaningful upstream difference or a Ruby-specific adaptation, add a dated note under this step before finishing.

Implementation note, 2026-05-05: Sinatra helpers now use `auth.api.get_session(headers:, return_headers: true)` instead of direct `BetterAuth::Session.find_current`, preserving core API plugin hooks and response cookies for app routes. `rake ci` required `RUBOCOP_CACHE_ROOT` in the writable temp directory because the sandbox blocked RuboCop's default `~/.cache` path.
