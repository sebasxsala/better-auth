# Enterprise Plugin Package Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Move Ruby enterprise/protocol plugins that are separate upstream packages into separate Ruby gems, starting with `better_auth-sso` and `better_auth-scim`, while keeping compatibility shims in `better_auth`.

**Architecture:** `better_auth` remains the framework-agnostic core gem and keeps plugins that upstream ships from `better-auth/plugins`, such as OIDC provider and MCP. Separate upstream packages get matching Ruby package boundaries: `@better-auth/sso` maps to `better_auth-sso`, `@better-auth/scim` maps to `better_auth-scim`, and `@better-auth/oauth-provider` maps to `better_auth-oauth-provider`. SAML is not the same thing as SSO; SAML is one protocol used inside upstream SSO, so the Ruby implementation folds SAML into `better_auth-sso` instead of exposing `better_auth-saml` as a package.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, existing BetterAuth plugin system, upstream Better Auth packages under `upstream/packages/sso`, `upstream/packages/scim`, `upstream/packages/oauth-provider`, `ruby-saml >= 1.18.1` owned by `better_auth-sso`.

---

## Timestamp And Naming

Created: `2026-04-27 18:34 CST`

Plan filename includes date, hour, and minute so future package-extraction plans sort predictably.

Execution note: implemented on 2026-04-27 without creating the plan's intermediate commits because `packages/better_auth/AGENTS.md` says not to commit unless explicitly requested. Follow-up correction: SAML was folded into `better_auth-sso` to match `upstream/packages/sso/src/saml`; `packages/better_auth-saml` should not exist as a separate Ruby package.

## Package Boundary Decisions

| Upstream package or plugin | Ruby destination | Reason |
| --- | --- | --- |
| `@better-auth/sso` | `packages/better_auth-sso` | Upstream installs SSO separately. SSO includes OIDC sign-in and SAML sign-in; it should not live as a first-class plugin implementation in core forever. |
| SAML support inside SSO | `packages/better_auth-sso/lib/better_auth/sso/saml.rb` | SAML is a protocol, not the whole SSO feature. Keeping `ruby-saml` outside core is correct, but the dependency belongs to SSO because upstream SAML lives inside `packages/sso`. |
| `@better-auth/scim` | `packages/better_auth-scim` | Upstream installs SCIM separately. SCIM is provisioning, not login. It can be used with SSO but should not depend on SSO. |
| `@better-auth/oauth-provider` | Later `packages/better_auth-oauth-provider` | Upstream installs OAuth provider separately. It is not the same as OIDC sign-in SSO. Defer until SSO and SCIM boundaries are stable. |
| `better-auth/plugins/oidc-provider` | Stay in `packages/better_auth` | Upstream exports OIDC provider from core `better-auth/plugins`, so no package split is needed for parity. |
| `better-auth/plugins/mcp` | Stay in `packages/better_auth` | Upstream MCP is currently core plugin surface, so no package split is needed for parity. |

## Terms For Future Agents

- SSO means Single Sign-On as a feature: users sign into this app through an external identity provider.
- SAML is an XML protocol that can power SSO.
- OIDC is an OAuth2-based identity protocol that can power SSO.
- SCIM is a provisioning API used by identity platforms to create, update, deactivate, and list users. SCIM is not login.
- OIDC provider means this app becomes an OIDC provider for other apps. That is different from SSO using OIDC.

## File Structure

### New SSO Package

- Create: `packages/better_auth-sso/better_auth-sso.gemspec`
  - Defines gem metadata, dependency on `better_auth`, development dependencies, and optional/development relationship to `better_auth-saml`.
- Create: `packages/better_auth-sso/Gemfile`
  - Uses local `better_auth` and the package gemspec.
- Create: `packages/better_auth-sso/Rakefile`
  - Runs Minitest and StandardRB for the package.
- Create: `packages/better_auth-sso/README.md`
  - Documents that apps install `better_auth-sso` for SSO and optionally `better_auth-saml` for real SAML XML validation.
- Create: `packages/better_auth-sso/CHANGELOG.md`
  - Starts package changelog.
- Create: `packages/better_auth-sso/lib/better_auth/sso.rb`
  - Public require path for `BetterAuth::SSO`.
- Create: `packages/better_auth-sso/lib/better_auth/sso/version.rb`
  - Package version.
- Create: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb`
  - Extracted SSO plugin implementation.
- Create: `packages/better_auth-sso/lib/better_auth/sso/saml_hooks.rb`
  - Small adapter boundary for merging `BetterAuth::SAML.sso_options` into SSO options.
- Create: `packages/better_auth-sso/test/test_helper.rb`
  - Local test setup.
- Create: `packages/better_auth-sso/test/better_auth/sso_test.rb`
  - Provider CRUD, sign-in selection, provider access, sanitization, and package load tests.
- Create: `packages/better_auth-sso/test/better_auth/sso_oidc_test.rb`
  - OIDC discovery/callback tests.
- Create: `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`
  - Core SAML flow, RelayState, replay, hooks, and adapter boundary tests.
- Move from core: `packages/better_auth/test/better_auth/plugins/sso_test.rb`
- Move from core: `packages/better_auth/test/better_auth/plugins/sso_oidc_test.rb`
- Move from core: `packages/better_auth/test/better_auth/plugins/sso_saml_test.rb`

### New SCIM Package

- Create: `packages/better_auth-scim/better_auth-scim.gemspec`
  - Defines gem metadata and dependency on `better_auth`.
- Create: `packages/better_auth-scim/Gemfile`
  - Uses local `better_auth` and the package gemspec.
- Create: `packages/better_auth-scim/Rakefile`
  - Runs Minitest and StandardRB for the package.
- Create: `packages/better_auth-scim/README.md`
  - Documents SCIM as provisioning, independent from SSO.
- Create: `packages/better_auth-scim/CHANGELOG.md`
  - Starts package changelog.
- Create: `packages/better_auth-scim/lib/better_auth/scim.rb`
  - Public require path for `BetterAuth::SCIM`.
- Create: `packages/better_auth-scim/lib/better_auth/scim/version.rb`
  - Package version.
- Create: `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`
  - Extracted SCIM plugin implementation.
- Create: `packages/better_auth-scim/test/test_helper.rb`
  - Local test setup.
- Create: `packages/better_auth-scim/test/better_auth/scim_test.rb`
  - Moved SCIM server parity tests.
- Move from core: `packages/better_auth/test/better_auth/plugins/scim_test.rb`

### Core Compatibility Shims

- Modify: `packages/better_auth/lib/better_auth.rb`
  - Stop requiring full SSO and SCIM implementations after package extraction.
  - Require small compatibility shims only.
- Create: `packages/better_auth/lib/better_auth/plugins/sso.rb`
  - Compatibility shim that loads `better_auth/sso` if installed and raises a clear error otherwise.
- Create: `packages/better_auth/lib/better_auth/plugins/scim.rb`
  - Compatibility shim that loads `better_auth/scim` if installed and raises a clear error otherwise.
- Modify: `packages/better_auth/better_auth.gemspec`
  - Do not add SSO/SCIM runtime dependencies. Core should stay small.
- Test: `packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb`
  - Verifies helpful errors when `BetterAuth::Plugins.sso` or `BetterAuth::Plugins.scim` are called without installing external gems.

### Documentation And Matrix

- Modify: `README.md`
  - Mark SSO and SCIM as external Ruby packages, not bundled core plugins.
  - Keep OIDC provider and MCP as core plugins.
- Modify: `.docs/features/sso.md`
  - Explain SSO package boundary and the SAML relationship.
- Modify: `.docs/features/scim.md`
  - Explain SCIM package boundary and independence from SSO.
- Modify: `.docs/features/upstream-parity-matrix.md`
  - Change SSO and SCIM implementation paths and package names.
  - Do not claim package split is complete until new package tests pass.
- Modify: `.docs/features/oauth-provider.md`
  - Add follow-up note that OAuth provider should become `better_auth-oauth-provider` in a later plan because upstream uses `@better-auth/oauth-provider`.

## Migration Policy

- Keep `BetterAuth::Plugins.sso(...)` and `BetterAuth::Plugins.scim(...)` as public entrypoints.
- After extraction, those entrypoints should be provided by the external gems.
- During transition, core shims may raise:

```ruby
raise LoadError, "BetterAuth::Plugins.sso requires the better_auth-sso gem. Add `gem \"better_auth-sso\"` and `require \"better_auth/sso\"`."
```

```ruby
raise LoadError, "BetterAuth::Plugins.scim requires the better_auth-scim gem. Add `gem \"better_auth-scim\"` and `require \"better_auth/scim\"`."
```

- Do not make `better_auth` depend on `better_auth-sso` or `better_auth-scim`.
- Do not make `better_auth-scim` depend on `better_auth-sso`.
- Do not make `better_auth-sso` require `ruby-saml` directly unless the team decides to fold `better_auth-saml` into SSO. Preferred first pass: keep `better_auth-saml` as optional companion.

## Task 1: Lock The Package Boundary In Docs First

**Files:**
- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/scim.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [x] **Step 1: Update SSO docs with protocol/package language.**

Add this section to `.docs/features/sso.md` after the summary:

```markdown
## Package Boundary

SSO is the app-facing plugin. SAML is only one protocol inside SSO, and OIDC is another protocol inside SSO. To match upstream `@better-auth/sso`, Ruby SSO should live in `better_auth-sso`.

`better_auth-saml` is not a replacement for `better_auth-sso`; it is an optional SAML XML validation companion that may be used behind the SSO gem so apps that do not use SAML avoid `ruby-saml`, Nokogiri, and XML-security dependencies.
```

- [x] **Step 2: Update SCIM docs with provisioning language.**

Add this section to `.docs/features/scim.md` after the summary:

```markdown
## Package Boundary

SCIM is provisioning, not login. It can be used alongside SSO in enterprise deployments, but it does not depend on SSO and SSO does not depend on SCIM.

To match upstream `@better-auth/scim`, Ruby SCIM should live in `better_auth-scim`.
```

- [x] **Step 3: Downgrade matrix wording from bundled-complete to extraction-in-progress.**

In `.docs/features/upstream-parity-matrix.md`, update the SSO and SCIM rows so their implementation paths point to desired package destinations:

```markdown
| `sso` | `upstream/packages/sso/src/`, `upstream/docs/content/docs/plugins/sso.mdx`, `upstream/docs/content/docs/guides/saml-sso-with-okta.mdx` | `upstream/packages/sso/src/**/*.test.ts` | Planned external package: `packages/better_auth-sso`; current transitional implementation: `packages/better_auth/lib/better_auth/plugins/sso.rb`, `packages/better_auth-saml/lib/better_auth/saml.rb` | Transitional tests: `packages/better_auth/test/better_auth/plugins/sso_test.rb`, `packages/better_auth/test/better_auth/plugins/sso_oidc_test.rb`, `packages/better_auth/test/better_auth/plugins/sso_saml_test.rb`, `packages/better_auth-saml/test/better_auth/saml_test.rb`; target tests: `packages/better_auth-sso/test/better_auth/*_test.rb` | `/sso/register`, `/sign-in/sso`, `/sso/callback/:providerId`, `/sso/saml2/callback/:providerId`, `/sso/saml2/sp/acs/:providerId`, `/sso/saml2/sp/metadata`, `/sso/providers`, `/sso/providers/:providerId`, `/sso/request-domain-verification`, `/sso/verify-domain` | `ssoProvider`, `verification`, `user`, `account`, `session` | Extraction planned | Upstream ships SSO as `@better-auth/sso`; Ruby should expose it through `better_auth-sso`. SAML is protocol support within SSO, not the package boundary. |
```

```markdown
| `scim` | `upstream/packages/scim/src/` | `upstream/packages/scim/src/scim.test.ts` | Planned external package: `packages/better_auth-scim`; current transitional implementation: `packages/better_auth/lib/better_auth/plugins/scim.rb` | Transitional test: `packages/better_auth/test/better_auth/plugins/scim_test.rb`; target test: `packages/better_auth-scim/test/better_auth/scim_test.rb` | `/scim/generate-token`, `/scim/v2/Users`, `/scim/v2/Users/:userId`, `/scim/v2/ServiceProviderConfig`, `/scim/v2/Schemas`, `/scim/v2/Schemas/:schemaId`, `/scim/v2/ResourceTypes`, `/scim/v2/ResourceTypes/:resourceTypeId` | `scimProvider`, `user.active`, `user.externalId` | Extraction planned | Upstream ships SCIM as `@better-auth/scim`; Ruby should expose it through `better_auth-scim`. SCIM remains independent from SSO. |
```

- [x] **Step 4: Run documentation search.**

Run:

```bash
rg -n "Package Boundary|Extraction planned|better_auth-sso|better_auth-scim|SAML is only one protocol|SCIM is provisioning" README.md .docs/features/sso.md .docs/features/scim.md .docs/features/upstream-parity-matrix.md
```

Expected: matches in SSO docs, SCIM docs, and parity matrix.

- [x] **Step 5: Commit docs boundary.**

Run:

```bash
git add README.md .docs/features/sso.md .docs/features/scim.md .docs/features/upstream-parity-matrix.md
git commit -m "docs: plan external enterprise plugin packages"
```

## Task 2: Create `better_auth-sso` Package Skeleton

**Files:**
- Create: `packages/better_auth-sso/better_auth-sso.gemspec`
- Create: `packages/better_auth-sso/Gemfile`
- Create: `packages/better_auth-sso/Rakefile`
- Create: `packages/better_auth-sso/README.md`
- Create: `packages/better_auth-sso/CHANGELOG.md`
- Create: `packages/better_auth-sso/lib/better_auth/sso.rb`
- Create: `packages/better_auth-sso/lib/better_auth/sso/version.rb`
- Create: `packages/better_auth-sso/test/test_helper.rb`

- [x] **Step 1: Write the gemspec.**

Create `packages/better_auth-sso/better_auth-sso.gemspec`:

```ruby
# frozen_string_literal: true

require_relative "lib/better_auth/sso/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-sso"
  spec.version = BetterAuth::SSO::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "SSO plugin package for Better Auth Ruby"
  spec.description = "Adds SSO provider management, OIDC SSO, and SAML SSO integration for Better Auth Ruby."
  spec.homepage = "https://github.com/sebasxsala/better-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth/blob/main/packages/better_auth-sso/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth/issues"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["LICENSE.md", "README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", "~> 0.1"

  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "standardrb", "~> 1.0"
end
```

- [x] **Step 2: Write package Gemfile.**

Create `packages/better_auth-sso/Gemfile`:

```ruby
# frozen_string_literal: true

source "https://rubygems.org"

ruby file: "../better_auth/.ruby-version"

gem "better_auth", path: "../better_auth"
gem "better_auth-saml", path: "../better_auth-saml"

gemspec name: "better_auth-sso"

group :development, :test do
  gem "minitest", "~> 5.25"
  gem "rake", "~> 13.2"
  gem "standardrb", "~> 1.0"
end
```

- [x] **Step 3: Write package Rakefile.**

Create `packages/better_auth-sso/Rakefile`:

```ruby
# frozen_string_literal: true

require "rake/testtask"
require "standard/rake"

Rake::TestTask.new(:test) do |task|
  task.libs << "test"
  task.pattern = "test/**/*_test.rb"
end

task default: [:test, :standard]
```

- [x] **Step 4: Write package version.**

Create `packages/better_auth-sso/lib/better_auth/sso/version.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SSO
    VERSION = "0.1.0"
  end
end
```

- [x] **Step 5: Write public require file.**

Create `packages/better_auth-sso/lib/better_auth/sso.rb`:

```ruby
# frozen_string_literal: true

require "better_auth"
require_relative "sso/version"
require_relative "../plugins/sso"

module BetterAuth
  module SSO
  end
end
```

- [x] **Step 6: Write README.**

Create `packages/better_auth-sso/README.md`:

```markdown
# Better Auth SSO

External SSO plugin package for `better_auth`.

SSO is the app-facing feature. It supports OIDC SSO and SAML SSO. SAML is not the same thing as SSO; SAML is one protocol used by SSO.

```ruby
require "better_auth"
require "better_auth/sso"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso
  ]
)
```

For real SAML XML validation, add `better_auth-saml` and merge its SAML options:

```ruby
require "better_auth/saml"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.sso(
      BetterAuth::SAML.sso_options
    )
  ]
)
```

SCIM is a separate provisioning feature and lives in `better_auth-scim`.
```

- [x] **Step 7: Write changelog.**

Create `packages/better_auth-sso/CHANGELOG.md`:

```markdown
# Changelog

## 0.1.0

- Initial package skeleton for Better Auth SSO.
```

- [x] **Step 8: Write test helper.**

Create `packages/better_auth-sso/test/test_helper.rb`:

```ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "better_auth"
require "better_auth/sso"
```

- [x] **Step 9: Verify package skeleton loads.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle install
rbenv exec bundle exec ruby -Ilib -e 'require "better_auth/sso"; puts BetterAuth::SSO::VERSION'
```

Expected output includes:

```text
0.1.0
```

- [x] **Step 10: Commit package skeleton.**

Run:

```bash
git add packages/better_auth-sso
git commit -m "feat: add better_auth-sso package skeleton"
```

## Task 3: Move SSO Implementation Into `better_auth-sso`

**Files:**
- Create: `packages/better_auth-sso/lib/better_auth/plugins/sso.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/sso.rb`
- Modify: `packages/better_auth/lib/better_auth.rb`
- Create: `packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb`

- [x] **Step 1: Copy current SSO implementation into new package.**

Copy the full current implementation from:

```text
packages/better_auth/lib/better_auth/plugins/sso.rb
```

to:

```text
packages/better_auth-sso/lib/better_auth/plugins/sso.rb
```

Keep the namespace as `BetterAuth::Plugins` and keep the public method as:

```ruby
def sso(options = {})
```

- [x] **Step 2: Replace core implementation with a shim.**

Replace `packages/better_auth/lib/better_auth/plugins/sso.rb` with:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def sso(*)
      require "better_auth/sso"
      BetterAuth::Plugins.sso(*)
    rescue LoadError
      raise LoadError, "BetterAuth::Plugins.sso requires the better_auth-sso gem. Add `gem \"better_auth-sso\"` and `require \"better_auth/sso\"`."
    end
  end
end
```

- [x] **Step 3: Remove eager SSO require from core loader.**

In `packages/better_auth/lib/better_auth.rb`, remove the full SSO implementation require if it exists as an eager plugin require. Keep only the shim require:

```ruby
require_relative "better_auth/plugins/sso"
```

- [x] **Step 4: Write shim failing test.**

Create `packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb`:

```ruby
# frozen_string_literal: true

require_relative "../../test_helper"

class ExternalPluginShimTest < Minitest::Test
  def test_sso_shim_has_helpful_error_when_external_package_is_missing
    error = assert_raises(LoadError) do
      BetterAuth::Plugins.sso
    end

    assert_includes error.message, "better_auth-sso"
    assert_includes error.message, "require \"better_auth/sso\""
  end
end
```

- [x] **Step 5: Run shim test and verify the helpful error path.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/external_plugin_shim_test.rb
```

Expected: PASS. If the local bundle can see `better_auth-sso`, replace the test body with this explicit `Kernel.require` stub before running it again:

```ruby
original_require = Kernel.method(:require)
Kernel.define_singleton_method(:require) do |path|
  raise LoadError if path == "better_auth/sso"
  original_require.call(path)
end

error = assert_raises(LoadError) do
  BetterAuth::Plugins.sso
end

assert_includes error.message, "better_auth-sso"
assert_includes error.message, "require \"better_auth/sso\""
```

- [x] **Step 6: Commit SSO move.**

Run:

```bash
git add packages/better_auth/lib/better_auth.rb packages/better_auth/lib/better_auth/plugins/sso.rb packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb packages/better_auth-sso/lib/better_auth/plugins/sso.rb
git commit -m "refactor: move sso plugin into external package"
```

## Task 4: Move SSO Tests Into `better_auth-sso`

**Files:**
- Create: `packages/better_auth-sso/test/better_auth/sso_test.rb`
- Create: `packages/better_auth-sso/test/better_auth/sso_oidc_test.rb`
- Create: `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`
- Delete after green: `packages/better_auth/test/better_auth/plugins/sso_test.rb`
- Delete after green: `packages/better_auth/test/better_auth/plugins/sso_oidc_test.rb`
- Delete after green: `packages/better_auth/test/better_auth/plugins/sso_saml_test.rb`

- [x] **Step 1: Move SSO test files.**

Move files:

```bash
mv packages/better_auth/test/better_auth/plugins/sso_test.rb packages/better_auth-sso/test/better_auth/sso_test.rb
mv packages/better_auth/test/better_auth/plugins/sso_oidc_test.rb packages/better_auth-sso/test/better_auth/sso_oidc_test.rb
mv packages/better_auth/test/better_auth/plugins/sso_saml_test.rb packages/better_auth-sso/test/better_auth/sso_saml_test.rb
```

- [x] **Step 2: Update moved test requires.**

At the top of each moved file, use:

```ruby
require_relative "../test_helper"
```

If a moved test previously needed core fixtures by relative path, require them through absolute repository-relative helper paths from `packages/better_auth/test` only after checking they are test utilities, not core test cases.

- [x] **Step 3: Run moved SSO tests.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle exec ruby -Itest test/better_auth/sso_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/sso_oidc_test.rb
rbenv exec bundle exec ruby -Itest test/better_auth/sso_saml_test.rb
```

Expected: all tests pass with the same assertions they had in core.

- [x] **Step 4: Run core tests that should no longer include SSO implementation tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/external_plugin_shim_test.rb
rbenv exec bundle exec rake test
```

Expected: core tests pass without SSO implementation test files.

- [x] **Step 5: Commit moved SSO tests.**

Run:

```bash
git add packages/better_auth/test/better_auth/plugins packages/better_auth-sso/test
git commit -m "test: move sso tests to external package"
```

## Task 5: Wire Optional SAML Companion Through SSO

**Files:**
- Create: `packages/better_auth-sso/lib/better_auth/sso/saml_hooks.rb`
- Modify: `packages/better_auth-sso/lib/better_auth/sso.rb`
- Modify: `packages/better_auth-sso/README.md`
- Test: `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`
- Test: `packages/better_auth-saml/test/better_auth/saml_test.rb`

- [x] **Step 1: Add SAML hook helper.**

Create `packages/better_auth-sso/lib/better_auth/sso/saml_hooks.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SSO
    module SAMLHooks
      module_function

      def merge_options(sso_options = {}, saml_options = {})
        sso_options = BetterAuth::Plugins.normalize_hash(sso_options || {})
        saml_options = BetterAuth::Plugins.normalize_hash(saml_options || {})
        sso_options.merge(saml_options) do |key, old_value, new_value|
          key == :saml ? BetterAuth::Plugins.normalize_hash(old_value || {}).merge(BetterAuth::Plugins.normalize_hash(new_value || {})) : new_value
        end
      end
    end
  end
end
```

- [x] **Step 2: Require helper from public SSO file.**

Modify `packages/better_auth-sso/lib/better_auth/sso.rb`:

```ruby
require_relative "sso/saml_hooks"
```

- [x] **Step 3: Add test for merging SAML options.**

Add to `packages/better_auth-sso/test/better_auth/sso_saml_test.rb`:

```ruby
def test_sso_saml_hooks_merge_without_requiring_ruby_saml
  base = {organization_provisioning: {role: "admin"}, saml: {validate_response: ->(**) { true }}}
  companion = {saml: {parse_response: ->(**) { {email: "ada@example.com"} }}}

  merged = BetterAuth::SSO::SAMLHooks.merge_options(base, companion)

  assert_equal "admin", merged.dig(:organization_provisioning, :role)
  assert merged.dig(:saml, :validate_response)
  assert merged.dig(:saml, :parse_response)
end
```

- [x] **Step 4: Run SSO and SAML package tests.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle exec ruby -Itest test/better_auth/sso_saml_test.rb
cd ../better_auth-saml
rbenv exec bundle exec ruby -Itest test/better_auth/saml_test.rb
```

Expected: both pass.

- [x] **Step 5: Commit SAML companion wiring.**

Run:

```bash
git add packages/better_auth-sso/lib/better_auth/sso.rb packages/better_auth-sso/lib/better_auth/sso/saml_hooks.rb packages/better_auth-sso/test/better_auth/sso_saml_test.rb packages/better_auth-sso/README.md
git commit -m "feat: wire optional saml companion through sso package"
```

## Task 6: Create `better_auth-scim` Package Skeleton

**Files:**
- Create: `packages/better_auth-scim/better_auth-scim.gemspec`
- Create: `packages/better_auth-scim/Gemfile`
- Create: `packages/better_auth-scim/Rakefile`
- Create: `packages/better_auth-scim/README.md`
- Create: `packages/better_auth-scim/CHANGELOG.md`
- Create: `packages/better_auth-scim/lib/better_auth/scim.rb`
- Create: `packages/better_auth-scim/lib/better_auth/scim/version.rb`
- Create: `packages/better_auth-scim/test/test_helper.rb`

- [x] **Step 1: Write SCIM gemspec.**

Create `packages/better_auth-scim/better_auth-scim.gemspec`:

```ruby
# frozen_string_literal: true

require_relative "lib/better_auth/scim/version"

Gem::Specification.new do |spec|
  spec.name = "better_auth-scim"
  spec.version = BetterAuth::SCIM::VERSION
  spec.authors = ["Sebastian Sala"]
  spec.email = ["sebastian.sala.tech@gmail.com"]

  spec.summary = "SCIM provisioning plugin package for Better Auth Ruby"
  spec.description = "Adds SCIM v2 token generation, metadata, and user provisioning routes for Better Auth Ruby."
  spec.homepage = "https://github.com/sebasxsala/better-auth"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sebasxsala/better-auth"
  spec.metadata["changelog_uri"] = "https://github.com/sebasxsala/better-auth/blob/main/packages/better_auth-scim/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "https://github.com/sebasxsala/better-auth/issues"

  spec.files = Dir.glob("lib/**/*", File::FNM_DOTMATCH).select { |file| File.file?(file) } +
    ["LICENSE.md", "README.md", "CHANGELOG.md"].select { |file| File.exist?(file) }
  spec.require_paths = ["lib"]

  spec.add_dependency "better_auth", "~> 0.1"

  spec.add_development_dependency "bundler", "~> 2.5"
  spec.add_development_dependency "minitest", "~> 5.25"
  spec.add_development_dependency "rake", "~> 13.2"
  spec.add_development_dependency "standardrb", "~> 1.0"
end
```

- [x] **Step 2: Write SCIM Gemfile.**

Create `packages/better_auth-scim/Gemfile`:

```ruby
# frozen_string_literal: true

source "https://rubygems.org"

ruby file: "../better_auth/.ruby-version"

gem "better_auth", path: "../better_auth"

gemspec name: "better_auth-scim"

group :development, :test do
  gem "minitest", "~> 5.25"
  gem "rake", "~> 13.2"
  gem "standardrb", "~> 1.0"
end
```

- [x] **Step 3: Write SCIM Rakefile.**

Create `packages/better_auth-scim/Rakefile`:

```ruby
# frozen_string_literal: true

require "rake/testtask"
require "standard/rake"

Rake::TestTask.new(:test) do |task|
  task.libs << "test"
  task.pattern = "test/**/*_test.rb"
end

task default: [:test, :standard]
```

- [x] **Step 4: Write SCIM version.**

Create `packages/better_auth-scim/lib/better_auth/scim/version.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module SCIM
    VERSION = "0.1.0"
  end
end
```

- [x] **Step 5: Write SCIM public require file.**

Create `packages/better_auth-scim/lib/better_auth/scim.rb`:

```ruby
# frozen_string_literal: true

require "better_auth"
require_relative "scim/version"
require_relative "../plugins/scim"

module BetterAuth
  module SCIM
  end
end
```

- [x] **Step 6: Write SCIM README.**

Create `packages/better_auth-scim/README.md`:

```markdown
# Better Auth SCIM

External SCIM provisioning plugin package for `better_auth`.

SCIM is not login. It is a provisioning API used by identity platforms to create, update, deactivate, and list users. It can be used alongside SSO, but it does not depend on SSO.

```ruby
require "better_auth"
require "better_auth/scim"

BetterAuth.auth(
  plugins: [
    BetterAuth::Plugins.scim
  ]
)
```
```

- [x] **Step 7: Write SCIM changelog.**

Create `packages/better_auth-scim/CHANGELOG.md`:

```markdown
# Changelog

## 0.1.0

- Initial package skeleton for Better Auth SCIM.
```

- [x] **Step 8: Write SCIM test helper.**

Create `packages/better_auth-scim/test/test_helper.rb`:

```ruby
# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "minitest/autorun"
require "better_auth"
require "better_auth/scim"
```

- [x] **Step 9: Verify SCIM package skeleton loads.**

Run:

```bash
cd packages/better_auth-scim
rbenv exec bundle install
rbenv exec bundle exec ruby -Ilib -e 'require "better_auth/scim"; puts BetterAuth::SCIM::VERSION'
```

Expected output includes:

```text
0.1.0
```

- [x] **Step 10: Commit SCIM skeleton.**

Run:

```bash
git add packages/better_auth-scim
git commit -m "feat: add better_auth-scim package skeleton"
```

## Task 7: Move SCIM Implementation Into `better_auth-scim`

**Files:**
- Create: `packages/better_auth-scim/lib/better_auth/plugins/scim.rb`
- Modify: `packages/better_auth/lib/better_auth/plugins/scim.rb`
- Modify: `packages/better_auth/lib/better_auth.rb`
- Modify: `packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb`

- [x] **Step 1: Copy current SCIM implementation into new package.**

Copy the full current implementation from:

```text
packages/better_auth/lib/better_auth/plugins/scim.rb
```

to:

```text
packages/better_auth-scim/lib/better_auth/plugins/scim.rb
```

Keep the namespace as `BetterAuth::Plugins` and keep the public method as:

```ruby
def scim(options = {})
```

- [x] **Step 2: Replace core SCIM implementation with a shim.**

Replace `packages/better_auth/lib/better_auth/plugins/scim.rb` with:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim(*)
      require "better_auth/scim"
      BetterAuth::Plugins.scim(*)
    rescue LoadError
      raise LoadError, "BetterAuth::Plugins.scim requires the better_auth-scim gem. Add `gem \"better_auth-scim\"` and `require \"better_auth/scim\"`."
    end
  end
end
```

- [x] **Step 3: Add SCIM shim test.**

Append to `packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb`:

```ruby
def test_scim_shim_has_helpful_error_when_external_package_is_missing
  error = assert_raises(LoadError) do
    BetterAuth::Plugins.scim
  end

  assert_includes error.message, "better_auth-scim"
  assert_includes error.message, "require \"better_auth/scim\""
end
```

- [x] **Step 4: Run shim tests.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/external_plugin_shim_test.rb
```

Expected: both SSO and SCIM shim tests pass.

- [x] **Step 5: Commit SCIM move.**

Run:

```bash
git add packages/better_auth/lib/better_auth.rb packages/better_auth/lib/better_auth/plugins/scim.rb packages/better_auth/test/better_auth/plugins/external_plugin_shim_test.rb packages/better_auth-scim/lib/better_auth/plugins/scim.rb
git commit -m "refactor: move scim plugin into external package"
```

## Task 8: Move SCIM Tests Into `better_auth-scim`

**Files:**
- Create: `packages/better_auth-scim/test/better_auth/scim_test.rb`
- Delete after green: `packages/better_auth/test/better_auth/plugins/scim_test.rb`

- [x] **Step 1: Move SCIM test file.**

Run:

```bash
mv packages/better_auth/test/better_auth/plugins/scim_test.rb packages/better_auth-scim/test/better_auth/scim_test.rb
```

- [x] **Step 2: Update moved test require.**

At the top of `packages/better_auth-scim/test/better_auth/scim_test.rb`, use:

```ruby
require_relative "../test_helper"
```

- [x] **Step 3: Run moved SCIM test.**

Run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec ruby -Itest test/better_auth/scim_test.rb
```

Expected: SCIM tests pass with the same assertions they had in core.

- [x] **Step 4: Run core tests after SCIM extraction.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/external_plugin_shim_test.rb
rbenv exec bundle exec rake test
```

Expected: core tests pass without SCIM implementation test files.

- [x] **Step 5: Commit moved SCIM tests.**

Run:

```bash
git add packages/better_auth/test/better_auth/plugins packages/better_auth-scim/test
git commit -m "test: move scim tests to external package"
```

## Task 9: Add Workspace-Level Package Verification

**Files:**
- Modify: root `Gemfile` or workspace documentation if one exists
- Modify: `README.md`
- Test: package test commands

- [x] **Step 1: Document package verification commands.**

Add this section to `README.md` under development or plugin package docs:

```markdown
### External Plugin Package Tests

```bash
cd packages/better_auth-sso
rbenv exec bundle exec rake

cd ../better_auth-scim
rbenv exec bundle exec rake

cd ../better_auth-saml
rbenv exec bundle exec rake
```
```

- [x] **Step 2: Run all external package tests.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle exec rake
cd ../better_auth-scim
rbenv exec bundle exec rake
cd ../better_auth-saml
rbenv exec bundle exec rake
```

Expected: all package tests and StandardRB checks pass.

- [x] **Step 3: Run core validation.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```

Expected: core tests and lint pass.

- [x] **Step 4: Commit verification docs.**

Run:

```bash
git add README.md
git commit -m "docs: add external plugin package verification"
```

## Task 10: Update Feature Docs After Extraction

**Files:**
- Modify: `.docs/features/sso.md`
- Modify: `.docs/features/scim.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Modify: `README.md`

- [x] **Step 1: Update SSO feature doc status.**

Set `.docs/features/sso.md` status to:

```markdown
Status: Extracted to `better_auth-sso`; SAML XML validation remains available through optional `better_auth-saml`.
```

- [x] **Step 2: Update SCIM feature doc status.**

Set `.docs/features/scim.md` status to:

```markdown
Status: Extracted to `better_auth-scim`.
```

- [x] **Step 3: Update README plugin table.**

Change the SSO row note to:

```markdown
External package: install `better_auth-sso`. Supports provider CRUD/access, OIDC discovery/callback, SAML ACS/callback/metadata, RelayState safety, replay protection, domain verification, and organization assignment. Real SAML XML validation is provided by optional `better_auth-saml`.
```

Change the SCIM row note to:

```markdown
External package: install `better_auth-scim`. Supports token envelopes, token storage modes, Bearer middleware, metadata, user CRUD, provider/org scoping, mappings, filters, PATCH operations, and organization enforcement.
```

- [x] **Step 4: Update parity matrix implementation paths.**

Set SSO implementation path to:

```markdown
`packages/better_auth-sso/lib/better_auth/plugins/sso.rb`, `packages/better_auth-saml/lib/better_auth/saml.rb`
```

Set SCIM implementation path to:

```markdown
`packages/better_auth-scim/lib/better_auth/plugins/scim.rb`
```

- [x] **Step 5: Run docs consistency search.**

Run:

```bash
rg -n "packages/better_auth/lib/better_auth/plugins/(sso|scim)\\.rb|better_auth-sso|better_auth-scim|better_auth-saml" README.md .docs/features
```

Expected: old core implementation paths appear only as compatibility shim notes, not as primary implementation paths.

- [x] **Step 6: Commit docs after extraction.**

Run:

```bash
git add README.md .docs/features/sso.md .docs/features/scim.md .docs/features/upstream-parity-matrix.md
git commit -m "docs: document extracted enterprise plugin packages"
```

## Task 11: Record Follow-Up For OAuth Provider Package

**Files:**
- Modify: `.docs/features/oauth-provider.md`
- Modify: `.docs/features/upstream-parity-matrix.md`
- Create in a later session: `.docs/plans/2026-04-27-1834-oauth-provider-package-extraction.md`

- [x] **Step 1: Add OAuth provider package note.**

Add this section to `.docs/features/oauth-provider.md`:

```markdown
## Package Boundary

Upstream ships OAuth provider as `@better-auth/oauth-provider`, not from core `better-auth/plugins`. Ruby should extract this to `better_auth-oauth-provider` after SSO and SCIM package boundaries are complete.

This is separate from OIDC provider. OIDC provider currently ships from upstream core plugin exports and should remain in `better_auth` unless upstream changes.
```

- [x] **Step 2: Update matrix note for OAuth provider.**

In `.docs/features/upstream-parity-matrix.md`, update OAuth provider notes with:

```markdown
Package extraction follow-up: upstream ships this as `@better-auth/oauth-provider`; Ruby should eventually expose `better_auth-oauth-provider`. This plan does not move OAuth provider yet.
```

- [x] **Step 3: Commit OAuth provider follow-up note.**

Run:

```bash
git add .docs/features/oauth-provider.md .docs/features/upstream-parity-matrix.md
git commit -m "docs: record oauth provider package extraction follow-up"
```

## Task 12: Final Validation

**Files:**
- All changed files

- [x] **Step 1: Run core validation.**

Run:

```bash
cd packages/better_auth
rbenv exec bundle exec rake test
rbenv exec bundle exec standardrb
```

Expected: all core tests and lint pass.

- [x] **Step 2: Run SSO package validation.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle exec rake
```

Expected: SSO package tests and lint pass.

- [x] **Step 3: Run SCIM package validation.**

Run:

```bash
cd packages/better_auth-scim
rbenv exec bundle exec rake
```

Expected: SCIM package tests and lint pass.

- [x] **Step 4: Run SAML companion validation.**

Run:

```bash
cd packages/better_auth-saml
rbenv exec bundle exec rake
```

Expected: SAML companion tests and lint pass.

- [x] **Step 5: Verify no old implementation tests remain in core.**

Run:

```bash
rg -n "class SSO|class SCIM|def test_.*sso|def test_.*scim" packages/better_auth/test/better_auth/plugins
```

Expected: only shim tests or unrelated references remain.

- [x] **Step 6: Verify package load paths.**

Run:

```bash
cd packages/better_auth-sso
rbenv exec bundle exec ruby -Ilib -e 'require "better_auth/sso"; p BetterAuth::Plugins.sso.id'
cd ../better_auth-scim
rbenv exec bundle exec ruby -Ilib -e 'require "better_auth/scim"; p BetterAuth::Plugins.scim.id'
```

Expected output:

```text
"sso"
"scim"
```

- [x] **Step 7: Commit final validation fixes if any.**

Run only if validation required fixes:

```bash
git add .
git commit -m "chore: finalize enterprise plugin package extraction"
```

## Self-Review

- Spec coverage: This plan covers the conversation points: SAML is not SSO, SSO should be an external package, SCIM should also be an external package, upstream separate package boundaries should guide Ruby packaging, OIDC provider and MCP should stay core for now, and OAuth provider gets an explicit follow-up because upstream also ships it separately.
- Placeholder scan: No placeholder-only tasks are intentionally left. Later OAuth provider extraction is explicitly out of scope and assigned to a future plan.
- Type consistency: Ruby package names use hyphenated gem names (`better_auth-sso`, `better_auth-scim`) and slash require paths (`better_auth/sso`, `better_auth/scim`). Public plugin calls remain `BetterAuth::Plugins.sso` and `BetterAuth::Plugins.scim`.
