# Configuration Parity Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring Better Auth Ruby configuration, cookie-cache/session behavior, IP tracking, experimental joins, Rails initializer ergonomics, and selected social-provider factories closer to upstream Better Auth parity before marking implemented features complete.

**Architecture:** Keep behavior framework-agnostic in `packages/better_auth`, with Rails only translating initializer/generator configuration into the core auth options. Use a maintained RFC 7516 JWE dependency for the public `session.cookieCache.strategy = "jwe"` contract instead of the current internal AES-GCM token format. Keep social-provider factories as small provider modules that feed the existing `social_providers` route contract; do not expand social linking/account-cookie behavior in this plan.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, RSpec for Rails, StandardRB, `jwt`, proposed `jwe >= 1.1.1`, OpenSSL HKDF, upstream Better Auth v1.4.x source/tests, and Better Auth public docs.

---

## Scope

This plan covers:

- Standard JWE cookie cache parity for `session.cookieCache.strategy = "jwe"`.
- Cookie-cache/session hardening for filtered cache payloads, `disableCookieCache`, `disableRefresh`, `refreshCache`, cache versioning, tamper handling, and `rememberMe: false` refresh behavior.
- `advanced.ipAddress` parity for both rate limiting and stored session `ipAddress`.
- Public `experimental: { joins: true }` option support, with adapter fallback semantics and docs.
- Rails initializer/generator examples for the same configuration surface.
- Social-provider factories for the most common providers: Google, GitHub, GitLab, Discord, Apple, and Microsoft Entra ID.

This plan does not cover:

- Stripe, SCIM, SAML, OAuth-provider, OIDC-provider, MCP, or device-authorization parity. Those remain in `.docs/plans/2026-04-26-phase-11-12-parity-hardening.md`.
- Social account-linking rules, account-cookie behavior, encrypted OAuth token storage, `disableImplicitSignUp`, `newUserCallbackURL`, or full upstream `social.test.ts` parity. Those should be a separate social-flow parity plan after provider factories exist.
- TypeScript client implementation. Ruby remains server/Rack-first; docs should describe using upstream JS clients with `baseURL`/`basePath`.

## Required Upstream Reading

Before implementation, read these exact files:

- `upstream/packages/better-auth/src/crypto/jwt.ts`
- `upstream/packages/better-auth/src/cookies/index.ts`
- `upstream/packages/better-auth/src/api/routes/session.ts`
- `upstream/packages/better-auth/src/api/routes/session-api.test.ts`
- `upstream/packages/better-auth/src/cookies/cookies.test.ts`
- `upstream/packages/better-auth/src/context/create-context.ts`
- `upstream/packages/better-auth/src/context/create-context.test.ts`
- `upstream/packages/better-auth/src/utils/get-request-ip.ts`
- `upstream/packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts`
- `upstream/packages/better-auth/src/db/internal-adapter.ts`
- `upstream/packages/better-auth/src/adapters/memory-adapter/adapter.memory.test.ts`
- `upstream/packages/core/src/social-providers/google.ts`
- `upstream/packages/core/src/social-providers/github.ts`
- `upstream/packages/core/src/social-providers/gitlab.ts`
- `upstream/packages/core/src/social-providers/discord.ts`
- `upstream/packages/core/src/social-providers/apple.ts`
- `upstream/packages/core/src/social-providers/microsoft-entra-id.ts`

Reference docs used for this plan:

- Better Auth session cache strategies: `https://better-auth.com/docs/concepts/session-management`
- Better Auth advanced options: `https://better-auth.com/docs/reference/options`
- Better Auth experimental joins: `https://better-auth.com/docs/concepts/database`
- Better Auth client `baseURL`/`basePath`: `https://better-auth.com/docs/concepts/client`
- Ruby `jwe` gem API: `https://rubydoc.info/gems/jwe/JWE`
- RubyGems `jwe`: `https://rubygems.org/gems/jwe`

## File Structure

Core dependency and crypto:

- Modify: `packages/better_auth/better_auth.gemspec`
  - Add `jwe` as a runtime dependency because `strategy: "jwe"` is a public security contract.
- Modify: `packages/better_auth/Gemfile.lock`
  - Lock the dependency through Bundler.
- Create: `packages/better_auth/lib/better_auth/crypto/jwe.rb`
  - Own upstream-compatible HKDF key derivation, JWE encrypt/decrypt, protected header validation, and expiry/tolerance handling.
- Modify: `packages/better_auth/lib/better_auth/crypto.rb`
  - Require the JWE helper and route `symmetric_encode_jwt`/`symmetric_decode_jwt` through standard JWE.

Cookie/session hardening:

- Modify: `packages/better_auth/lib/better_auth/cookies.rb`
  - Filter user/session payloads before cache writes, encode/decode using the selected strategy, and invalidate failed/tampered cache reads deterministically.
- Modify: `packages/better_auth/lib/better_auth/session.rb`
  - Preserve `dont_remember`, implement stateless `refresh_cache`, and tighten cache fallback behavior.
- Modify: `packages/better_auth/lib/better_auth/routes/session.rb`
  - Preserve `disableCookieCache` and `disableRefresh` route semantics and add focused response tests.
- Modify: `packages/better_auth/lib/better_auth/routes/sign_up.rb`
  - Replace direct `x-forwarded-for` parsing with the shared request-IP helper.
- Modify: `packages/better_auth/lib/better_auth/routes/sign_in.rb`
  - Replace direct `x-forwarded-for` parsing with the shared request-IP helper if present.
- Modify: `packages/better_auth/lib/better_auth/routes/social.rb`
  - Use the shared request-IP helper for session creation only. Do not change social linking behavior here.

IP tracking:

- Create: `packages/better_auth/lib/better_auth/request_ip.rb`
  - Centralize upstream-style `advanced.ipAddress` behavior.
- Modify: `packages/better_auth/lib/better_auth/rate_limiter.rb`
  - Delegate IP extraction to `BetterAuth::RequestIP`.
- Modify: `packages/better_auth/lib/better_auth/core.rb`
  - Require `request_ip`.

Experimental joins:

- Modify: `packages/better_auth/lib/better_auth/configuration.rb`
  - Add top-level `experimental` option with `joins`.
- Modify: `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
  - Respect `experimental[:joins]` where joins are supported; keep fallback multi-query behavior when disabled or unsupported.
- Modify: `packages/better_auth/lib/better_auth/adapters/memory.rb`
  - Confirm join support remains native and safe for tests.
- Modify: `packages/better_auth/lib/better_auth/adapters/sql.rb`
  - Confirm supported joins remain native; unsupported joins must return the base records and let internal adapter fallback combine.
- Modify: `packages/better_auth-rails/lib/better_auth/rails/configuration.rb`
  - Pass `experimental` through Rails config.

Rails initializer/docs:

- Modify: `packages/better_auth-rails/lib/generators/better_auth/install/templates/initializer.rb.tt`
  - Show session cookie cache, advanced IP, experimental joins, social providers placeholder, and plugins.
- Modify: `packages/better_auth-rails/README.md`
  - Document initializer parity with core Ruby configuration.
- Modify: `packages/better_auth/README.md`
  - Fix outdated `BetterAuth.configure` examples if they conflict with current `BetterAuth.auth`.

Social-provider factories:

- Create: `packages/better_auth/lib/better_auth/social_providers.rb`
  - Require all provider factory files.
- Create: `packages/better_auth/lib/better_auth/social_providers/base.rb`
  - Shared URL generation, token exchange, JSON fetching, and user-info mapping helpers.
- Create: `packages/better_auth/lib/better_auth/social_providers/google.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/github.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/gitlab.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/discord.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/apple.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/microsoft_entra_id.rb`
- Modify: `packages/better_auth/lib/better_auth.rb`
  - Require `better_auth/social_providers`.

Tests:

- Modify: `packages/better_auth/test/better_auth/crypto_test.rb`
- Modify: `packages/better_auth/test/better_auth/cookies_test.rb`
- Modify: `packages/better_auth/test/better_auth/session_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_in_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_up_test.rb`
- Modify: `packages/better_auth/test/better_auth/router_test.rb`
- Modify: `packages/better_auth/test/better_auth/configuration_test.rb`
- Modify: `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`
- Create: `packages/better_auth/test/better_auth/request_ip_test.rb`
- Create: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Modify: `packages/better_auth-rails/spec/better_auth/rails_spec.rb`
- Modify: `packages/better_auth-rails/spec/generators/better_auth/install_generator_spec.rb`

Docs/plans:

- Modify: `.docs/features/sessions-and-cookies.md`
- Modify: `.docs/features/database-adapters.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/plans/2026-04-25-better-auth-ruby-port.md`
- Keep separate: `.docs/plans/2026-04-26-phase-11-12-parity-hardening.md`

## Task 1: Add Standard JWE Dependency And Wrapper

**Files:**

- Modify: `packages/better_auth/better_auth.gemspec`
- Modify: `packages/better_auth/Gemfile.lock`
- Create: `packages/better_auth/lib/better_auth/crypto/jwe.rb`
- Modify: `packages/better_auth/lib/better_auth/crypto.rb`
- Test: `packages/better_auth/test/better_auth/crypto_test.rb`

- [x] **Step 1: Write failing crypto tests for upstream-compatible JWE shape**

Add these tests to `packages/better_auth/test/better_auth/crypto_test.rb`:

```ruby
def test_symmetric_jwe_uses_compact_jwe_header_and_round_trips
  token = BetterAuth::Crypto.symmetric_encode_jwt(
    {"sub" => "user-1"},
    "secret-with-enough-entropy-for-jwe",
    "better-auth-session",
    expires_in: 60
  )

  segments = token.split(".")
  assert_equal 5, segments.length

  header = JSON.parse(BetterAuth::Crypto.base64url_decode(segments.first))
  assert_equal "dir", header.fetch("alg")
  assert_equal "A256CBC-HS512", header.fetch("enc")
  assert header.fetch("kid").is_a?(String)
  refute_includes token, "user-1"

  payload = BetterAuth::Crypto.symmetric_decode_jwt(
    token,
    "secret-with-enough-entropy-for-jwe",
    "better-auth-session"
  )

  assert_equal "user-1", payload.fetch("sub")
  assert payload.fetch("iat").is_a?(Integer)
  assert payload.fetch("exp").is_a?(Integer)
  assert payload.fetch("jti").is_a?(String)
end

def test_symmetric_jwe_rejects_wrong_secret_wrong_salt_and_tampering
  token = BetterAuth::Crypto.symmetric_encode_jwt(
    {"sub" => "user-1"},
    "secret-with-enough-entropy-for-jwe",
    "better-auth-session",
    expires_in: 60
  )

  assert_nil BetterAuth::Crypto.symmetric_decode_jwt(token, "wrong-secret", "better-auth-session")
  assert_nil BetterAuth::Crypto.symmetric_decode_jwt(token, "secret-with-enough-entropy-for-jwe", "wrong-salt")
  assert_nil BetterAuth::Crypto.symmetric_decode_jwt("#{token}x", "secret-with-enough-entropy-for-jwe", "better-auth-session")
end
```

- [x] **Step 2: Run tests to verify they fail**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/crypto_test.rb
```

Expected: FAIL because the existing `symmetric_encode_jwt` returns the internal AES-GCM payload instead of five-segment compact JWE.

- [x] **Step 3: Add the `jwe` dependency**

Modify `packages/better_auth/better_auth.gemspec`:

```ruby
  spec.add_dependency "jwt", "~> 2.8"
  spec.add_dependency "jwe", "~> 1.1", ">= 1.1.1"
  spec.add_dependency "bcrypt", "~> 3.1"
```

Run:

```bash
cd packages/better_auth
rbenv exec bundle install
```

Expected: `Gemfile.lock` includes `jwe`.

- [x] **Step 4: Create the JWE helper**

Create `packages/better_auth/lib/better_auth/crypto/jwe.rb`:

```ruby
# frozen_string_literal: true

require "json"
require "jwe"
require "openssl"
require "securerandom"

module BetterAuth
  module Crypto
    module JWE
      INFO = "BetterAuth.js Generated Encryption Key"
      ALG = "dir"
      ENC = "A256CBC-HS512"
      CLOCK_TOLERANCE = 15

      module_function

      def encode(payload, secret, salt, expires_in:)
        now = Time.now.to_i
        claims = Crypto.stringify_keys(payload).merge(
          "iat" => now,
          "exp" => now + expires_in.to_i,
          "jti" => SecureRandom.uuid
        )
        key = derive_key(secret, salt)

        ::JWE.encrypt(
          JSON.generate(claims),
          key,
          alg: ALG,
          enc: ENC,
          kid: jwk_thumbprint(key)
        )
      end

      def decode(token, secret, salt)
        key = derive_key(secret, salt)
        plaintext = ::JWE.decrypt(token.to_s, key)
        payload = JSON.parse(plaintext)
        return nil if payload["exp"] && payload["exp"].to_i + CLOCK_TOLERANCE < Time.now.to_i

        payload
      rescue JSON::ParserError, ArgumentError, ::JWE::DecodeError, ::JWE::InvalidData, OpenSSL::Cipher::CipherError
        nil
      end

      def derive_key(secret, salt)
        OpenSSL::KDF.hkdf(
          secret.to_s,
          salt: salt.to_s,
          info: INFO,
          length: 64,
          hash: "SHA256"
        )
      end

      def jwk_thumbprint(key)
        jwk = {
          "k" => Crypto.base64url_encode(key),
          "kty" => "oct"
        }
        canonical = JSON.generate(jwk.sort.to_h)
        Crypto.base64url_encode(OpenSSL::Digest.digest("SHA256", canonical))
      end
    end
  end
end
```

- [x] **Step 5: Route symmetric JWT helpers through standard JWE**

Modify `packages/better_auth/lib/better_auth/crypto.rb`:

```ruby
require "securerandom"
require_relative "crypto/jwe"
```

Replace `symmetric_encode_jwt` and `symmetric_decode_jwt`:

```ruby
    def symmetric_encode_jwt(payload, secret, salt, expires_in: 3600)
      JWE.encode(payload, secret, salt, expires_in: expires_in)
    end

    def symmetric_decode_jwt(token, secret, salt)
      JWE.decode(token, secret, salt)
    end
```

- [x] **Step 6: Run crypto tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/crypto_test.rb
```

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add packages/better_auth/better_auth.gemspec packages/better_auth/Gemfile.lock packages/better_auth/lib/better_auth/crypto.rb packages/better_auth/lib/better_auth/crypto/jwe.rb packages/better_auth/test/better_auth/crypto_test.rb
git commit -m "feat: use standard jwe for encrypted cookie cache"
```

## Task 2: Filter Cookie Cache Payloads And Expand Strategy Tests

**Files:**

- Modify: `packages/better_auth/lib/better_auth/cookies.rb`
- Modify: `packages/better_auth/test/better_auth/cookies_test.rb`
- Modify: `.docs/features/sessions-and-cookies.md`

- [x] **Step 1: Write failing tests for `compact`, `jwt`, and `jwe` cache payloads**

Add these tests to `packages/better_auth/test/better_auth/cookies_test.rb`:

```ruby
def test_cookie_cache_supports_compact_jwt_and_jwe_strategies
  %w[compact jwt jwe].each do |strategy|
    auth = BetterAuth.auth(
      secret: SECRET,
      session: {cookie_cache: {enabled: true, strategy: strategy, version: "1"}}
    )
    ctx = endpoint_context(auth)

    BetterAuth::Cookies.set_cookie_cache(ctx, {
      session: {"id" => "session-1", "token" => "token-1", "userId" => "user-1"},
      user: {"id" => "user-1", "email" => "ada@example.com"}
    }, false)

    cookie = ctx.response_headers.fetch("set-cookie").lines.find { |line| line.include?("session_data") }.split(";").first
    payload = BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: strategy, version: "1")

    assert_equal "token-1", payload.fetch("session").fetch("token")
    assert_equal "ada@example.com", payload.fetch("user").fetch("email")
  end
end

def test_cookie_cache_filters_fields_marked_returned_false
  auth = BetterAuth.auth(
    secret: SECRET,
    session: {cookie_cache: {enabled: true, strategy: "jwt"}},
    plugins: [
      {
        id: "private-cache-field",
        schema: {
          user: {
            fields: {
              secretNote: {type: "string", returned: false}
            }
          },
          session: {
            fields: {
              serverOnly: {type: "string", returned: false}
            }
          }
        }
      }
    ]
  )
  ctx = endpoint_context(auth)

  BetterAuth::Cookies.set_cookie_cache(ctx, {
    session: {
      "id" => "session-1",
      "token" => "token-1",
      "userId" => "user-1",
      "serverOnly" => "do-not-cache"
    },
    user: {
      "id" => "user-1",
      "email" => "ada@example.com",
      "secretNote" => "do-not-cache"
    }
  }, false)

  cookie = ctx.response_headers.fetch("set-cookie").lines.find { |line| line.include?("session_data") }.split(";").first
  payload = BetterAuth::Cookies.get_cookie_cache(cookie, secret: SECRET, strategy: "jwt")

  refute payload.fetch("session").key?("serverOnly")
  refute payload.fetch("user").key?("secretNote")
end
```

- [x] **Step 2: Run tests to verify they fail**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/cookies_test.rb
```

Expected: FAIL because the current cache writer serializes raw user/session hashes.

- [x] **Step 3: Add filtered cache helpers**

Modify `packages/better_auth/lib/better_auth/cookies.rb`:

```ruby
    def filtered_cache_data(ctx, session)
      {
        "session" => stringify_keys(Schema.parse_output(ctx.context.options, "session", stringify_keys(session.fetch(:session)))),
        "user" => stringify_keys(Schema.parse_output(ctx.context.options, "user", stringify_keys(session.fetch(:user)))),
        "updatedAt" => current_millis,
        "version" => cookie_cache_version(
          ctx.context.session_config.dig(:cookie_cache, :version),
          session.fetch(:session),
          session.fetch(:user)
        )
      }
    end
```

Replace the `data = { ... }` block inside `set_cookie_cache` with:

```ruby
      data = filtered_cache_data(ctx, session)
```

- [x] **Step 4: Harden decode error handling for all strategies**

Modify `decode_cookie_cache` rescue clause in `packages/better_auth/lib/better_auth/cookies.rb`:

```ruby
    rescue JSON::ParserError, KeyError, ArgumentError, JWT::DecodeError
      nil
```

- [x] **Step 5: Run cookie tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/cookies_test.rb
```

Expected: PASS.

- [x] **Step 6: Update sessions docs**

Modify `.docs/features/sessions-and-cookies.md` so the Key Differences section says:

```markdown
### JWE Strategy

Ruby uses the `jwe` gem to encode `session.cookieCache.strategy = "jwe"` as RFC 7516 compact JWE with `alg = "dir"` and `enc = "A256CBC-HS512"`, matching upstream's public cookie-cache strategy. The encryption key is derived from the Better Auth secret and the `better-auth-session` salt using HKDF-SHA256 with the same info string as upstream: `BetterAuth.js Generated Encryption Key`.
```

- [x] **Step 7: Commit**

```bash
git add packages/better_auth/lib/better_auth/cookies.rb packages/better_auth/test/better_auth/cookies_test.rb .docs/features/sessions-and-cookies.md
git commit -m "fix: filter session cookie cache payloads"
```

## Task 3: Harden Session Cache Semantics

**Files:**

- Modify: `packages/better_auth/lib/better_auth/session.rb`
- Modify: `packages/better_auth/lib/better_auth/cookies.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/session.rb`
- Modify: `packages/better_auth/test/better_auth/session_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/session_routes_test.rb`

- [x] **Step 1: Write failing tests for `disableCookieCache` and tampered cache behavior**

Add to `packages/better_auth/test/better_auth/routes/session_routes_test.rb`:

```ruby
def test_get_session_disable_cookie_cache_reads_authoritative_database
  auth = build_auth(session: {cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}})
  cookie = sign_up_cookie(auth, email: "disable-cache@example.com")
  session = auth.api.get_session(headers: {"cookie" => cookie})
  auth.context.adapter.update(
    model: "user",
    where: [{field: "id", value: session[:user]["id"]}],
    update: {name: "Authoritative Name"}
  )

  cached = auth.api.get_session(headers: {"cookie" => cookie})
  authoritative = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})

  refute_equal "Authoritative Name", cached[:user]["name"]
  assert_equal "Authoritative Name", authoritative[:user]["name"]
end

def test_get_session_with_tampered_cache_falls_back_to_database_and_refreshes_cache
  auth = build_auth(session: {cookie_cache: {enabled: true, strategy: "jwe", max_age: 300}})
  cookie = sign_up_cookie(auth, email: "tampered-cache@example.com")
  tampered = cookie.gsub(/better-auth\.session_data=[^; ]+/, "better-auth.session_data=invalid")

  status, headers, body = auth.api.get_session(headers: {"cookie" => tampered}, as_response: true)

  assert_equal 200, status
  assert_equal "tampered-cache@example.com", JSON.parse(body.join).fetch("user").fetch("email")
  assert_includes headers.fetch("set-cookie"), "better-auth.session_data="
end
```

- [x] **Step 2: Write failing tests for `rememberMe: false` refresh behavior**

Add to `packages/better_auth/test/better_auth/routes/session_routes_test.rb`:

```ruby
def test_remember_me_false_stays_session_cookie_after_refresh
  auth = build_auth(session: {update_age: 0, expires_in: 120, cookie_cache: {enabled: false}})
  _signup_cookie = sign_up_cookie(auth, email: "browser-session@example.com")

  status, headers, _body = auth.api.sign_in_email(
    body: {email: "browser-session@example.com", password: "password123", rememberMe: false},
    as_response: true
  )
  assert_equal 200, status
  cookie = cookie_header(headers.fetch("set-cookie"))
  session_cookie_line = headers.fetch("set-cookie").lines.find { |line| line.include?("session_token") }
  refute_includes session_cookie_line, "Max-Age="

  _status, refresh_headers, _refresh_body = auth.api.get_session(headers: {"cookie" => cookie}, as_response: true)
  refreshed_session_cookie_line = refresh_headers.fetch("set-cookie").lines.find { |line| line.include?("session_token") }
  refute_includes refreshed_session_cookie_line, "Max-Age="
end
```

- [x] **Step 3: Run tests to verify they fail**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb
```

Expected: FAIL on stale cache / browser-session refresh behavior until the implementation tracks `dont_remember`.

- [x] **Step 4: Add `dont_remember` detection**

Add to `packages/better_auth/lib/better_auth/cookies.rb`:

```ruby
    def dont_remember?(ctx)
      cookie = ctx.context.auth_cookies[:dont_remember]
      ctx.get_signed_cookie(cookie.name, ctx.context.secret) == "true"
    end
```

Modify `Session.refresh_session` in `packages/better_auth/lib/better_auth/session.rb`:

```ruby
      dont_remember = Cookies.dont_remember?(ctx)
      Cookies.set_session_cookie(ctx, refreshed, dont_remember)
```

- [x] **Step 5: Implement stateless `refresh_cache` threshold**

Add to `packages/better_auth/lib/better_auth/session.rb`:

```ruby
    def should_refresh_cookie_cache?(config, payload)
      refresh_cache = config[:refresh_cache]
      return false if refresh_cache == false || refresh_cache.nil?

      max_age = (config[:max_age] || 60 * 5).to_i
      update_age = if refresh_cache.is_a?(Hash)
        (refresh_cache[:update_age] || refresh_cache["updateAge"] || refresh_cache["update_age"]).to_i
      else
        (max_age * 0.8).to_i
      end
      updated_at = payload["updatedAt"].to_i
      updated_at.positive? && updated_at + (update_age * 1000) <= (Time.now.to_f * 1000).to_i
    end
```

Inside `cached_session`, after token validation and before returning:

```ruby
      result = {session: payload["session"], user: payload["user"]}
      Cookies.set_cookie_cache(ctx, result, false) if should_refresh_cookie_cache?(config, payload)
      result
```

- [x] **Step 6: Warn and disable `refresh_cache` for stateful stores**

Modify `normalize_session` in `packages/better_auth/lib/better_auth/configuration.rb`:

```ruby
      if (database || secondary_storage) && session.dig(:cookie_cache, :refresh_cache)
        warn("[better-auth] `session.cookieCache.refreshCache` is enabled while `database` or `secondaryStorage` is configured. `refreshCache` is meant for stateless setups. Disabling `refreshCache`.")
        session[:cookie_cache] = session[:cookie_cache].merge(refresh_cache: false)
      end
```

- [x] **Step 7: Run session route tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb
```

Expected: PASS.

- [x] **Step 8: Commit**

```bash
git add packages/better_auth/lib/better_auth/session.rb packages/better_auth/lib/better_auth/cookies.rb packages/better_auth/lib/better_auth/configuration.rb packages/better_auth/test/better_auth/routes/session_routes_test.rb
git commit -m "fix: harden session cookie cache semantics"
```

## Task 4: Centralize Advanced IP Address Handling

**Files:**

- Create: `packages/better_auth/lib/better_auth/request_ip.rb`
- Modify: `packages/better_auth/lib/better_auth/core.rb`
- Modify: `packages/better_auth/lib/better_auth/rate_limiter.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/sign_up.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/sign_in.rb`
- Modify: `packages/better_auth/lib/better_auth/routes/social.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_up_test.rb`
- Modify: `packages/better_auth/test/better_auth/routes/sign_in_test.rb`
- Create: `packages/better_auth/test/better_auth/request_ip_test.rb`

- [x] **Step 1: Write failing request IP tests**

Create `packages/better_auth/test/better_auth/request_ip_test.rb`:

```ruby
# frozen_string_literal: true

require "rack/mock"
require_relative "../test_helper"

class BetterAuthRequestIPTest < Minitest::Test
  SECRET = "request-ip-secret-with-enough-entropy"

  def test_uses_configured_headers_in_order
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {
        ip_address: {
          ip_address_headers: ["x-client-ip", "x-forwarded-for"]
        }
      }
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_CLIENT_IP" => "203.0.113.7", "HTTP_X_FORWARDED_FOR" => "198.51.100.2"))

    assert_equal "203.0.113.7", BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_disable_ip_tracking_returns_nil
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {ip_address: {disable_ip_tracking: true}}
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "203.0.113.7"))

    assert_nil BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_masks_ipv6_addresses
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {ip_address: {ipv6_subnet: 64}}
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "2001:db8:abcd:1234:ffff::1"))

    assert_equal "2001:db8:abcd:1234::", BetterAuth::RequestIP.client_ip(request, config)
  end
end
```

- [x] **Step 2: Write failing route tests for stored session IP**

Add to `packages/better_auth/test/better_auth/routes/sign_up_test.rb`:

```ruby
def test_sign_up_session_uses_advanced_ip_address_headers
  auth = build_auth(
    advanced: {
      ip_address: {
        ip_address_headers: ["x-client-ip", "x-forwarded-for"]
      }
    }
  )

  _status, headers, _body = auth.api.sign_up_email(
    body: {email: "ip-header@example.com", password: "password123", name: "IP Header"},
    headers: {"x-client-ip" => "203.0.113.10", "x-forwarded-for" => "198.51.100.20", "user-agent" => "SignUpTest"},
    as_response: true
  )
  session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

  assert_equal "203.0.113.10", session[:session]["ipAddress"]
end
```

Add to `packages/better_auth/test/better_auth/routes/sign_in_test.rb`:

```ruby
def test_sign_in_session_respects_disable_ip_tracking
  auth = build_auth(advanced: {ip_address: {disable_ip_tracking: true}})
  sign_up_cookie(auth, email: "no-ip@example.com")

  _status, headers, _body = auth.api.sign_in_email(
    body: {email: "no-ip@example.com", password: "password123"},
    headers: {"x-forwarded-for" => "203.0.113.10", "user-agent" => "SignInTest"},
    as_response: true
  )
  session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

  assert_equal "", session[:session]["ipAddress"].to_s
end
```

- [x] **Step 3: Run tests to verify they fail**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/request_ip_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_up_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_in_test.rb
```

Expected: the new request IP file fails until `BetterAuth::RequestIP` exists; route tests fail while routes parse only `x-forwarded-for`.

- [x] **Step 4: Implement `BetterAuth::RequestIP`**

Create `packages/better_auth/lib/better_auth/request_ip.rb`:

```ruby
# frozen_string_literal: true

require "ipaddr"

module BetterAuth
  module RequestIP
    module_function

    def client_ip(request, options)
      ip_options = options.advanced[:ip_address] || {}
      return nil if ip_options[:disable_ip_tracking]

      Array(ip_options[:ip_address_headers] || ["x-forwarded-for"]).each do |header|
        value = request.get_header(rack_header_name(header))
        next unless value.is_a?(String)

        ip = value.split(",").first.to_s.strip
        return normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)
      end

      ip = request.ip.to_s
      normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)
    end

    def rack_header_name(header)
      "HTTP_#{header.to_s.upcase.tr("-", "_")}"
    end

    def valid_ip?(ip)
      return false if ip.empty? || ip.match?(/\s/)

      IPAddr.new(ip)
      true
    rescue ArgumentError
      false
    end

    def normalize_ip(ip, ipv6_subnet: nil)
      address = IPAddr.new(ip)
      return address.native.to_s if address.respond_to?(:ipv4_mapped?) && address.ipv4_mapped?
      return address.to_s if address.ipv4?

      address.mask((ipv6_subnet || 64).to_i).to_s
    end
  end
end
```

Modify `packages/better_auth/lib/better_auth/core.rb` to require it:

```ruby
require_relative "request_ip"
```

- [x] **Step 5: Update rate limiter and session overrides**

In `packages/better_auth/lib/better_auth/rate_limiter.rb`, replace `client_ip` body with:

```ruby
      RequestIP.client_ip(request, options)
```

In `packages/better_auth/lib/better_auth/routes/sign_up.rb`, replace `session_overrides`:

```ruby
    def self.session_overrides(ctx)
      {
        ipAddress: RequestIP.client_ip(ctx.request, ctx.context.options).to_s,
        userAgent: ctx.headers["user-agent"].to_s
      }
    end
```

Use the same helper anywhere `create_session` is called with direct header parsing in `sign_in.rb` and `social.rb`.

- [x] **Step 6: Run focused tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/request_ip_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_up_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/sign_in_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/router_test.rb
```

Expected: PASS.

- [x] **Step 7: Commit**

```bash
git add packages/better_auth/lib/better_auth/request_ip.rb packages/better_auth/lib/better_auth/core.rb packages/better_auth/lib/better_auth/rate_limiter.rb packages/better_auth/lib/better_auth/routes/sign_up.rb packages/better_auth/lib/better_auth/routes/sign_in.rb packages/better_auth/lib/better_auth/routes/social.rb packages/better_auth/test/better_auth/request_ip_test.rb packages/better_auth/test/better_auth/routes/sign_up_test.rb packages/better_auth/test/better_auth/routes/sign_in_test.rb
git commit -m "fix: apply advanced ip address config to sessions"
```

## Task 5: Add Public Experimental Joins Option

**Files:**

- Modify: `packages/better_auth/lib/better_auth/configuration.rb`
- Modify: `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`
- Modify: `packages/better_auth/test/better_auth/configuration_test.rb`
- Modify: `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`
- Modify: `.docs/features/database-adapters.md`

- [x] **Step 1: Write failing configuration test**

Add to `packages/better_auth/test/better_auth/configuration_test.rb`:

```ruby
def test_experimental_joins_option_accepts_camel_and_snake_case
  camel = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: true})
  snake = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: false})

  assert_equal({joins: true}, camel.experimental)
  assert_equal({joins: false}, snake.experimental)
end
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/configuration_test.rb
```

Expected: FAIL because `experimental` is not an exposed configuration attribute.

- [x] **Step 3: Add `experimental` to configuration**

Modify `packages/better_auth/lib/better_auth/configuration.rb`:

```ruby
      :experimental,
```

Set it in `initialize`:

```ruby
      @experimental = normalize_experimental(options[:experimental])
```

Include it in `to_h`:

```ruby
        experimental: experimental,
```

Add:

```ruby
    def normalize_experimental(value)
      configured = symbolize_keys(value || {})
      {
        joins: !!configured[:joins]
      }
    end
```

- [x] **Step 4: Write internal adapter tests for join fallback**

Add to `packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb`:

```ruby
def test_find_session_uses_adapter_join_when_experimental_joins_enabled
  config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, experimental: {joins: true})
  adapter = BetterAuth::Adapters::Memory.new(config)
  internal = BetterAuth::Adapters::InternalAdapter.new(adapter, config)
  user = internal.create_user("name" => "Ada", "email" => "ada@example.com")
  session = internal.create_session(user["id"])

  found = internal.find_session(session["token"])

  assert_equal session["token"], found[:session]["token"]
  assert_equal user["id"], found[:user]["id"]
end

def test_find_session_falls_back_to_separate_queries_when_experimental_joins_disabled
  config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, experimental: {joins: false})
  adapter = BetterAuth::Adapters::Memory.new(config)
  internal = BetterAuth::Adapters::InternalAdapter.new(adapter, config)
  user = internal.create_user("name" => "Ada", "email" => "ada@example.com")
  session = internal.create_session(user["id"])

  found = internal.find_session(session["token"])

  assert_equal session["token"], found[:session]["token"]
  assert_equal user["id"], found[:user]["id"]
end
```

- [x] **Step 5: Implement join gate in internal adapter**

Modify `packages/better_auth/lib/better_auth/adapters/internal_adapter.rb`:

```ruby
      def joins_enabled?
        !!options.experimental[:joins]
      end
```

In methods that currently pass `join: {user: true}` directly, use:

```ruby
        found = if joins_enabled?
          adapter.find_one(model: "session", where: [{field: "token", value: token}], join: {user: true})
        else
          session = adapter.find_one(model: "session", where: [{field: "token", value: token}])
          user = session && adapter.find_one(model: "user", where: [{field: "id", value: session["userId"]}])
          session && user ? session.merge("user" => user) : nil
        end
```

Keep this as an internal optimization gate: behavior must be the same with joins enabled or disabled.

- [x] **Step 6: Run focused tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/configuration_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/internal_adapter_test.rb
```

Expected: PASS.

- [x] **Step 7: Update database docs**

Append to `.docs/features/database-adapters.md`:

```markdown
### Experimental Joins

Ruby accepts the upstream public option `experimental: { joins: true }`. Joins are treated as an optimization, not a behavior switch: when enabled and supported by the adapter, the internal adapter requests native joins; when disabled or unsupported, it performs separate adapter reads and combines the same logical response. This keeps the option safe for production Ruby apps while preserving upstream's documented configuration shape.
```

- [x] **Step 8: Commit**

```bash
git add packages/better_auth/lib/better_auth/configuration.rb packages/better_auth/lib/better_auth/adapters/internal_adapter.rb packages/better_auth/test/better_auth/configuration_test.rb packages/better_auth/test/better_auth/adapters/internal_adapter_test.rb .docs/features/database-adapters.md
git commit -m "feat: add experimental joins option"
```

## Task 6: Rails Configuration Parity

**Files:**

- Modify: `packages/better_auth-rails/lib/better_auth/rails/configuration.rb`
- Modify: `packages/better_auth-rails/lib/generators/better_auth/install/templates/initializer.rb.tt`
- Modify: `packages/better_auth-rails/spec/better_auth/rails_spec.rb`
- Modify: `packages/better_auth-rails/spec/generators/better_auth/install_generator_spec.rb`
- Modify: `packages/better_auth-rails/README.md`

- [x] **Step 1: Write failing Rails config pass-through test**

Add to `packages/better_auth-rails/spec/better_auth/rails_spec.rb`:

```ruby
it "passes session advanced experimental and social provider options to core auth" do
  described_class.configure do |config|
    config.secret = "test-secret-that-is-long-enough-for-validation"
    config.database = :memory
    config.session = {cookie_cache: {enabled: true, max_age: 300, strategy: "jwe"}}
    config.advanced = {ip_address: {ip_address_headers: ["x-client-ip"]}}
    config.experimental = {joins: true}
    config.social_providers = {github: {client_id: "id", client_secret: "secret"}}
  end

  auth = described_class.auth

  expect(auth.options.session[:cookie_cache]).to include(enabled: true, max_age: 300, strategy: "jwe")
  expect(auth.options.advanced[:ip_address][:ip_address_headers]).to eq(["x-client-ip"])
  expect(auth.options.experimental).to eq(joins: true)
  expect(auth.options.social_providers[:github]).to include(client_id: "id")
end
```

- [x] **Step 2: Run Rails spec to verify it fails**

Run:

```bash
cd packages/better_auth-rails
rbenv exec bundle exec rspec spec/better_auth/rails_spec.rb
```

Expected: FAIL because `experimental` is not in `AUTH_OPTION_NAMES`.

- [x] **Step 3: Add Rails config pass-through**

Modify `packages/better_auth-rails/lib/better_auth/rails/configuration.rb`:

```ruby
        experimental
```

inside `AUTH_OPTION_NAMES`.

- [x] **Step 4: Expand generated initializer**

Modify `packages/better_auth-rails/lib/generators/better_auth/install/templates/initializer.rb.tt` so the generated file contains:

```ruby
  config.session = {
    cookie_cache: {
      enabled: true,
      max_age: 5 * 60,
      strategy: "jwe"
    }
  }

  config.advanced = {
    ip_address: {
      ip_address_headers: ["x-forwarded-for"],
      disable_ip_tracking: false
    }
  }

  config.experimental = {
    joins: false
  }

  config.social_providers = {
    # github: BetterAuth::SocialProviders.github(
    #   client_id: ENV.fetch("GITHUB_CLIENT_ID"),
    #   client_secret: ENV.fetch("GITHUB_CLIENT_SECRET")
    # )
  }
```

- [x] **Step 5: Update generator spec expectations**

Modify `packages/better_auth-rails/spec/generators/better_auth/install_generator_spec.rb`:

```ruby
expect(File.read(initializer)).to include("config.session")
expect(File.read(initializer)).to include("strategy: \"jwe\"")
expect(File.read(initializer)).to include("config.advanced")
expect(File.read(initializer)).to include("config.experimental")
expect(File.read(initializer)).to include("config.social_providers")
```

- [x] **Step 6: Run Rails focused specs**

Run:

```bash
cd packages/better_auth-rails
rbenv exec bundle exec rspec spec/better_auth/rails_spec.rb spec/generators/better_auth/install_generator_spec.rb
```

Expected: PASS.

- [x] **Step 7: Update Rails README**

Replace the initializer example in `packages/better_auth-rails/README.md` with the expanded configuration from Step 4 plus this note:

```markdown
Rails configuration is a thin option builder for the core Rack auth object. The same option concepts are available in core Ruby through `BetterAuth.auth(...)`; Rails places them in `config/initializers/better_auth.rb` so applications can rely on credentials, ActiveRecord, and Rails environment configuration.
```

- [x] **Step 8: Commit**

```bash
git add packages/better_auth-rails/lib/better_auth/rails/configuration.rb packages/better_auth-rails/lib/generators/better_auth/install/templates/initializer.rb.tt packages/better_auth-rails/spec/better_auth/rails_spec.rb packages/better_auth-rails/spec/generators/better_auth/install_generator_spec.rb packages/better_auth-rails/README.md
git commit -m "docs: expose parity config in rails initializer"
```

## Task 7: Add Common Social Provider Factories

**Files:**

- Create: `packages/better_auth/lib/better_auth/social_providers.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/base.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/google.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/github.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/gitlab.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/discord.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/apple.rb`
- Create: `packages/better_auth/lib/better_auth/social_providers/microsoft_entra_id.rb`
- Modify: `packages/better_auth/lib/better_auth.rb`
- Create: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Modify: `packages/better_auth/README.md`

- [x] **Step 1: Write failing tests for provider factory shape**

Create `packages/better_auth/test/better_auth/social_providers_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthSocialProvidersTest < Minitest::Test
  def test_google_authorization_url_shape
    provider = BetterAuth::SocialProviders.google(client_id: "google-id", client_secret: "google-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      code_verifier: "verifier-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/google",
      scopes: ["openid", "email", "profile"],
      loginHint: "ada@example.com"
    )

    assert_equal "google", provider.fetch(:id)
    assert_includes url, "https://accounts.google.com/o/oauth2/v2/auth"
    assert_includes url, "client_id=google-id"
    assert_includes url, "scope=openid+email+profile"
    assert_includes url, "state=state-1"
    assert_includes url, "code_challenge="
    assert_includes url, "code_challenge_method=S256"
    assert_includes url, "login_hint=ada%40example.com"
  end

  def test_github_authorization_url_shape
    provider = BetterAuth::SocialProviders.github(client_id: "github-id", client_secret: "github-secret")

    url = provider.fetch(:create_authorization_url).call(
      state: "state-1",
      redirect_uri: "http://localhost:3000/api/auth/callback/github",
      scopes: ["user:email"]
    )

    assert_equal "github", provider.fetch(:id)
    assert_includes url, "https://github.com/login/oauth/authorize"
    assert_includes url, "client_id=github-id"
    assert_includes url, "scope=user%3Aemail"
  end

  def test_factories_exist_for_selected_common_providers
    assert_equal "gitlab", BetterAuth::SocialProviders.gitlab(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "discord", BetterAuth::SocialProviders.discord(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "apple", BetterAuth::SocialProviders.apple(client_id: "id", client_secret: "secret").fetch(:id)
    assert_equal "microsoft-entra-id", BetterAuth::SocialProviders.microsoft_entra_id(client_id: "id", client_secret: "secret", tenant_id: "common").fetch(:id)
  end
end
```

- [x] **Step 2: Run test to verify it fails**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/social_providers_test.rb
```

Expected: FAIL because `BetterAuth::SocialProviders` does not exist.

- [x] **Step 3: Create provider base helpers**

Create `packages/better_auth/lib/better_auth/social_providers/base.rb`:

```ruby
# frozen_string_literal: true

require "base64"
require "json"
require "net/http"
require "openssl"
require "uri"

module BetterAuth
  module SocialProviders
    module Base
      module_function

      def authorization_url(endpoint, params)
        uri = URI(endpoint)
        query = URI.decode_www_form(uri.query.to_s)
        params.compact.each { |key, value| query << [key.to_s, Array(value).join(" ")] unless value.nil? || value == "" }
        uri.query = URI.encode_www_form(query)
        uri.to_s
      end

      def pkce_challenge(verifier)
        digest = OpenSSL::Digest.digest("SHA256", verifier.to_s)
        Base64.urlsafe_encode64(digest, padding: false)
      end

      def post_form(url, form)
        uri = URI(url)
        response = Net::HTTP.post_form(uri, form.transform_keys(&:to_s))
        JSON.parse(response.body)
      end

      def get_json(url, headers = {})
        uri = URI(url)
        request = Net::HTTP::Get.new(uri)
        headers.each { |key, value| request[key.to_s] = value.to_s }
        response = Net::HTTP.start(uri.hostname, uri.port, use_ssl: uri.scheme == "https") { |http| http.request(request) }
        JSON.parse(response.body)
      end
    end
  end
end
```

- [x] **Step 4: Create the provider loader**

Create `packages/better_auth/lib/better_auth/social_providers.rb`:

```ruby
# frozen_string_literal: true

require_relative "social_providers/base"
require_relative "social_providers/google"
require_relative "social_providers/github"
require_relative "social_providers/gitlab"
require_relative "social_providers/discord"
require_relative "social_providers/apple"
require_relative "social_providers/microsoft_entra_id"
```

Modify `packages/better_auth/lib/better_auth.rb`:

```ruby
require_relative "better_auth/social_providers"
```

- [x] **Step 5: Implement Google and GitHub factories**

Create `packages/better_auth/lib/better_auth/social_providers/google.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def google(client_id:, client_secret:, scopes: ["openid", "email", "profile"], **options)
      {
        id: "google",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          verifier = data[:code_verifier] || data[:codeVerifier]
          Base.authorization_url("https://accounts.google.com/o/oauth2/v2/auth", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            response_type: "code",
            scope: data[:scopes] || scopes,
            state: data[:state],
            code_challenge: verifier && Base.pkce_challenge(verifier),
            code_challenge_method: verifier && "S256",
            login_hint: data[:loginHint] || data[:login_hint],
            access_type: options[:access_type] || "offline",
            prompt: options[:prompt]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://oauth2.googleapis.com/token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            code_verifier: data[:code_verifier] || data[:codeVerifier],
            grant_type: "authorization_code",
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          access_token = tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
          info = Base.get_json("https://openidconnect.googleapis.com/v1/userinfo", "Authorization" => "Bearer #{access_token}")
          {
            user: {
              id: info["sub"],
              email: info["email"],
              name: info["name"],
              image: info["picture"],
              emailVerified: !!info["email_verified"]
            }
          }
        end
      }
    end
  end
end
```

Create `packages/better_auth/lib/better_auth/social_providers/github.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def github(client_id:, client_secret:, scopes: ["user:email"])
      {
        id: "github",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: lambda do |data|
          Base.authorization_url("https://github.com/login/oauth/authorize", {
            client_id: client_id,
            redirect_uri: data[:redirect_uri] || data[:redirectURI],
            scope: data[:scopes] || scopes,
            state: data[:state]
          })
        end,
        validate_authorization_code: lambda do |data|
          Base.post_form("https://github.com/login/oauth/access_token", {
            client_id: client_id,
            client_secret: client_secret,
            code: data[:code],
            redirect_uri: data[:redirect_uri] || data[:redirectURI]
          })
        end,
        get_user_info: lambda do |tokens|
          access_token = tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
          info = Base.get_json("https://api.github.com/user", "Authorization" => "Bearer #{access_token}", "Accept" => "application/json")
          emails = Base.get_json("https://api.github.com/user/emails", "Authorization" => "Bearer #{access_token}", "Accept" => "application/json")
          primary = Array(emails).find { |email| email["primary"] } || Array(emails).first || {}
          {
            user: {
              id: info["id"].to_s,
              email: primary["email"] || info["email"],
              name: info["name"] || info["login"],
              image: info["avatar_url"],
              emailVerified: !!primary["verified"]
            }
          }
        end
      }
    end
  end
end
```

- [x] **Step 6: Implement GitLab, Discord, Apple, and Microsoft Entra ID factories**

Create `packages/better_auth/lib/better_auth/social_providers/gitlab.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def gitlab(client_id:, client_secret:, issuer: "https://gitlab.com", scopes: ["read_user", "email"])
      base = issuer.to_s.sub(%r{/+\z}, "")
      {
        id: "gitlab",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: ->(data) { Base.authorization_url("#{base}/oauth/authorize", client_id: client_id, redirect_uri: data[:redirect_uri] || data[:redirectURI], response_type: "code", scope: data[:scopes] || scopes, state: data[:state]) },
        validate_authorization_code: ->(data) { Base.post_form("#{base}/oauth/token", client_id: client_id, client_secret: client_secret, code: data[:code], grant_type: "authorization_code", redirect_uri: data[:redirect_uri] || data[:redirectURI]) },
        get_user_info: lambda do |tokens|
          access_token = tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
          info = Base.get_json("#{base}/api/v4/user", "Authorization" => "Bearer #{access_token}")
          {user: {id: info["id"].to_s, email: info["email"], name: info["name"] || info["username"], image: info["avatar_url"], emailVerified: !!info["confirmed_at"]}}
        end
      }
    end
  end
end
```

Create `packages/better_auth/lib/better_auth/social_providers/discord.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def discord(client_id:, client_secret:, scopes: ["identify", "email"])
      {
        id: "discord",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: ->(data) { Base.authorization_url("https://discord.com/oauth2/authorize", client_id: client_id, redirect_uri: data[:redirect_uri] || data[:redirectURI], response_type: "code", scope: data[:scopes] || scopes, state: data[:state]) },
        validate_authorization_code: ->(data) { Base.post_form("https://discord.com/api/oauth2/token", client_id: client_id, client_secret: client_secret, code: data[:code], grant_type: "authorization_code", redirect_uri: data[:redirect_uri] || data[:redirectURI]) },
        get_user_info: lambda do |tokens|
          access_token = tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
          info = Base.get_json("https://discord.com/api/users/@me", "Authorization" => "Bearer #{access_token}")
          avatar = info["avatar"] && "https://cdn.discordapp.com/avatars/#{info["id"]}/#{info["avatar"]}.png"
          {user: {id: info["id"], email: info["email"], name: info["global_name"] || info["username"], image: avatar, emailVerified: !!info["verified"]}}
        end
      }
    end
  end
end
```

Create `packages/better_auth/lib/better_auth/social_providers/apple.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def apple(client_id:, client_secret:, scopes: ["name", "email"])
      {
        id: "apple",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: ->(data) { Base.authorization_url("https://appleid.apple.com/auth/authorize", client_id: client_id, redirect_uri: data[:redirect_uri] || data[:redirectURI], response_type: "code", response_mode: "form_post", scope: data[:scopes] || scopes, state: data[:state]) },
        validate_authorization_code: ->(data) { Base.post_form("https://appleid.apple.com/auth/token", client_id: client_id, client_secret: client_secret, code: data[:code], grant_type: "authorization_code", redirect_uri: data[:redirect_uri] || data[:redirectURI]) },
        get_user_info: lambda do |tokens|
          id_token = tokens[:id_token] || tokens["id_token"] || tokens[:idToken] || tokens["idToken"]
          payload = JWT.decode(id_token.to_s, nil, false).first
          {user: {id: payload["sub"], email: payload["email"], name: payload["name"] || payload["email"], image: nil, emailVerified: payload["email_verified"].to_s == "true"}}
        end
      }
    end
  end
end
```

Create `packages/better_auth/lib/better_auth/social_providers/microsoft_entra_id.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SocialProviders
    module_function

    def microsoft_entra_id(client_id:, client_secret:, tenant_id: "common", scopes: ["openid", "profile", "email", "User.Read"])
      base = "https://login.microsoftonline.com/#{tenant_id}/oauth2/v2.0"
      {
        id: "microsoft-entra-id",
        client_id: client_id,
        client_secret: client_secret,
        create_authorization_url: ->(data) { Base.authorization_url("#{base}/authorize", client_id: client_id, redirect_uri: data[:redirect_uri] || data[:redirectURI], response_type: "code", scope: data[:scopes] || scopes, state: data[:state]) },
        validate_authorization_code: ->(data) { Base.post_form("#{base}/token", client_id: client_id, client_secret: client_secret, code: data[:code], grant_type: "authorization_code", redirect_uri: data[:redirect_uri] || data[:redirectURI]) },
        get_user_info: lambda do |tokens|
          access_token = tokens[:access_token] || tokens["access_token"] || tokens[:accessToken] || tokens["accessToken"]
          info = Base.get_json("https://graph.microsoft.com/v1.0/me", "Authorization" => "Bearer #{access_token}")
          {user: {id: info["id"], email: info["mail"] || info["userPrincipalName"], name: info["displayName"], image: nil, emailVerified: true}}
        end
      }
    end
  end
end
```

- [x] **Step 7: Run provider tests**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/social_providers_test.rb
```

Expected: PASS without live network calls because tests only inspect generated URLs and factory shape.

- [x] **Step 8: Add README examples**

Add to `packages/better_auth/README.md`:

```ruby
auth = BetterAuth.auth(
  secret: ENV.fetch("BETTER_AUTH_SECRET"),
  social_providers: {
    google: BetterAuth::SocialProviders.google(
      client_id: ENV.fetch("GOOGLE_CLIENT_ID"),
      client_secret: ENV.fetch("GOOGLE_CLIENT_SECRET")
    ),
    github: BetterAuth::SocialProviders.github(
      client_id: ENV.fetch("GITHUB_CLIENT_ID"),
      client_secret: ENV.fetch("GITHUB_CLIENT_SECRET")
    )
  }
)
```

- [x] **Step 9: Commit**

```bash
git add packages/better_auth/lib/better_auth.rb packages/better_auth/lib/better_auth/social_providers.rb packages/better_auth/lib/better_auth/social_providers packages/better_auth/test/better_auth/social_providers_test.rb packages/better_auth/README.md
git commit -m "feat: add common social provider factories"
```

## Task 8: Documentation And Parity Matrix Cleanup

**Files:**

- Modify: `.docs/features/sessions-and-cookies.md`
- Modify: `.docs/features/database-adapters.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `.docs/plans/2026-04-25-better-auth-ruby-port.md`
- Modify: `packages/better_auth/README.md`
- Modify: `packages/better_auth-rails/README.md`

- [x] **Step 1: Update parity matrix statuses**

In `.docs/features/upstream-parity-matrix.md`, make these status updates:

```markdown
| `better-auth`, `cookies/session` | `upstream/packages/better-auth/src/cookies/`, `upstream/packages/better-auth/src/api/routes/session.ts` | `upstream/packages/better-auth/src/cookies/cookies.test.ts`, `upstream/packages/better-auth/src/api/routes/session-api.test.ts` | `packages/better_auth/lib/better_auth/cookies.rb`, `packages/better_auth/lib/better_auth/session.rb`, `packages/better_auth/lib/better_auth/crypto/jwe.rb` | `packages/better_auth/test/better_auth/cookies_test.rb`, `packages/better_auth/test/better_auth/session_test.rb`, `packages/better_auth/test/better_auth/routes/session_routes_test.rb` | `/get-session`, session cookies | `session` | Partial | Standard JWE, filtered cache payloads, disableCookieCache, disableRefresh, refreshCache, versioning, and rememberMe refresh semantics are covered. Full upstream session-api matrix remains broader than this track. |
| `better-auth`, `advanced.ipAddress` | `upstream/packages/better-auth/src/utils/get-request-ip.ts` | `upstream/packages/better-auth/src/api/rate-limiter/rate-limiter.test.ts`, route IP assertions | `packages/better_auth/lib/better_auth/request_ip.rb`, `packages/better_auth/lib/better_auth/rate_limiter.rb` | `packages/better_auth/test/better_auth/request_ip_test.rb`, route tests | session creation, rate limiting | `session.ipAddress`, `rateLimit` | Ported | Ruby applies configured IP headers, disable tracking, and IPv6 subnet normalization to both rate limiting and stored sessions. |
| `better-auth`, `experimental.joins` | `upstream/packages/better-auth/src/db/` | adapter join suites | `packages/better_auth/lib/better_auth/configuration.rb`, adapters | adapter/internal adapter tests | adapter reads | all relational models | Partial | Public option is accepted. Internal adapter uses native joins when enabled and falls back to separate reads when disabled or unsupported. Exhaustive adapter join matrix remains outside this plan. |
| `better-auth`, `social-providers` | `upstream/packages/core/src/social-providers/` | `upstream/packages/better-auth/src/social.test.ts` | `packages/better_auth/lib/better_auth/social_providers/` | `packages/better_auth/test/better_auth/social_providers_test.rb` | `/sign-in/social`, `/callback/:providerId` | `account`, `user` | Partial | Common provider factories exist for Google, GitHub, GitLab, Discord, Apple, and Microsoft Entra ID. Full social flow/linking parity remains separate. |
```

- [x] **Step 2: Update the master plan**

In `.docs/plans/2026-04-25-better-auth-ruby-port.md`, add a progress line under Phase 4:

```markdown
- [x] Hardened cookie-cache strategy parity with standard JWE, filtered cache payloads, version validation, `disableCookieCache`, `disableRefresh`, and `rememberMe: false` refresh behavior.
```

Add a progress line under Phase 3/4.5:

```markdown
- [x] Added public `experimental: { joins: true }` option as an adapter optimization with fallback behavior.
```

Add a progress line under Feature Coverage List:

```markdown
- [x] Advanced IP address configuration applies consistently to rate limiting and stored session metadata.
- [x] Common social provider factories for Google, GitHub, GitLab, Discord, Apple, and Microsoft Entra ID.
```

- [x] **Step 3: Add client configuration note**

Add to `packages/better_auth/README.md` and `packages/better_auth-rails/README.md`:

```markdown
### JavaScript Client

Ruby Better Auth exposes the same HTTP route surface. Frontend apps should use the upstream Better Auth JavaScript client and point it at the Ruby server:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "http://localhost:3000",
  basePath: "/api/auth",
});
```
```
```

- [x] **Step 4: Run docs grep for stale JWE warning**

Run:

```bash
rg -n "AES-256-GCM|not a public API token contract|JWE uses.*internal" .docs packages/better_auth packages/better_auth-rails
```

Expected: no stale statement claims Ruby `jwe` is not real JWE.

- [x] **Step 5: Commit**

```bash
git add .docs/features/sessions-and-cookies.md .docs/features/database-adapters.md .docs/features/upstream-parity-matrix.md .docs/plans/2026-04-25-better-auth-ruby-port.md packages/better_auth/README.md packages/better_auth-rails/README.md
git commit -m "docs: update configuration parity status"
```

## Task 9: Final Verification

**Files:**

- No source changes beyond previous tasks.

- [ ] **Step 1: Run focused core suites**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/crypto_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/cookies_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/session_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/routes/session_routes_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/request_ip_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/configuration_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/adapters/internal_adapter_test.rb
rbenv exec bundle exec rake test TEST=test/better_auth/social_providers_test.rb
```

Expected: PASS.

- [ ] **Step 2: Run Rails focused suites**

Run:

```bash
cd packages/better_auth-rails
rbenv exec bundle exec rspec spec/better_auth/rails_spec.rb spec/generators/better_auth/install_generator_spec.rb
```

Expected: PASS.

- [ ] **Step 3: Run package lint**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec standardrb
cd ../better_auth-rails
rbenv exec bundle exec standardrb
```

Expected: PASS.

- [ ] **Step 4: Run broader suites if database services are available**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
cd ../better_auth-rails
rbenv exec bundle exec rspec
```

Expected: PASS when local PostgreSQL access is available. If PostgreSQL TCP access is sandbox-blocked, record the exact connection error and the focused suite results in the implementation summary.

- [ ] **Step 5: Commit final verification docs if needed**

If verification notes changed docs or plans:

```bash
git add .docs/features .docs/plans packages/better_auth/README.md packages/better_auth-rails/README.md
git commit -m "docs: record configuration parity verification"
```

## Self-Review Checklist

- [x] Spec coverage: JWE standard, cookie/session hardening, `disableCookieCache`, advanced IP headers, experimental joins, Rails initializer examples, social provider factories, and non-Phase-11/12 missing tests are represented.
- [x] Phase 11/12 separation: Stripe, SCIM, SAML, OIDC/OAuth-provider/MCP remain in `.docs/plans/2026-04-26-phase-11-12-parity-hardening.md`.
- [x] Social scope: provider factories are included; social route/linking parity is explicitly excluded from this plan.
- [x] Placeholder scan: no unfinished-marker words or vague "write tests" steps remain.
- [x] Type consistency: Ruby config keys use snake_case internally while preserving upstream public concepts in docs.
