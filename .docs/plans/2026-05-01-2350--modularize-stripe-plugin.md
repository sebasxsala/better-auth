# Stripe Plugin Modularization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modularize `better_auth-stripe` so the Ruby package mirrors upstream `upstream/packages/stripe` file boundaries closely enough to make missing functions, endpoint behavior, and tests visible.

**Architecture:** Keep `BetterAuth::Plugins.stripe` and `require "better_auth/stripe"` as the stable public Ruby API, but split the current 1,292-line `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb` into focused `BetterAuth::Stripe` modules matching upstream `index.ts`, `routes.ts`, `hooks.ts`, `schema.ts`, `utils.ts`, `metadata.ts`, `middleware.ts`, `error-codes.ts`, and `types.ts`. Ruby-only adaptations stay explicit: no browser client port, no TypeScript type declarations, no zod schemas, and synchronous Ruby adapters are acceptable where Better Auth Ruby has no async equivalent.

**Tech Stack:** Ruby 3.2+, Minitest, StandardRB, `better_auth`, `better_auth-stripe`, Stripe Ruby SDK, upstream Better Auth `v1.6.9` TypeScript source under `upstream/packages/stripe`.

---

## Required Context

- [x] Read root `AGENTS.md`.
- [x] Checked for package-level `packages/better_auth-stripe/AGENTS.md`; none exists.
- [x] Reviewed current Ruby package files under `packages/better_auth-stripe`.
- [x] Reviewed upstream Stripe files under `upstream/packages/stripe`.
- [x] Confirmed upstream submodule is already present.
- [x] Noted unrelated dirty files: `.github/workflows/ci.yml` and `.github/workflows/release.yml`; do not touch them.

## Source Of Truth

- [ ] Treat `upstream/packages/stripe/src` as the source of truth for behavior.
- [ ] Treat upstream tests as the parity checklist:
  - `upstream/packages/stripe/test/stripe.test.ts`
  - `upstream/packages/stripe/test/stripe-organization.test.ts`
  - `upstream/packages/stripe/test/seat-based-billing.test.ts`
  - `upstream/packages/stripe/test/utils.test.ts`
  - `upstream/packages/stripe/test/metadata.test.ts`
- [ ] Preserve Ruby behavior already covered in:
  - `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`
  - `packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb`
- [ ] Update this plan whenever a Ruby-specific adaptation is chosen.
- [ ] Do not bump `packages/better_auth-stripe/lib/better_auth/stripe/version.rb` unless this work is explicitly released.

## Current Ruby State

- [x] Public loader exists: `packages/better_auth-stripe/lib/better_auth/stripe.rb`.
- [x] Public plugin file exists: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`.
- [x] Core package lazy loader exists: `packages/better_auth/lib/better_auth/plugins/stripe.rb`.
- [x] Current plugin implementation is one large file with these responsibilities:
  - Stripe Ruby SDK client adapter.
  - Error codes.
  - Plugin factory.
  - Schema generation.
  - Endpoint factory and all endpoint bodies.
  - Webhook dispatch and webhook handlers.
  - User/customer hooks.
  - Organization hooks and seat sync.
  - Plan/price/subscription utilities.
  - Metadata merge and extraction helpers.
  - URL/search/key normalization helpers.
- [x] Current Ruby tests are broad but monolithic:
  - `stripe_test.rb`: 1,668 lines.
  - `stripe_organization_test.rb`: 769 lines.

## Upstream File Map

- [ ] `upstream/packages/stripe/src/index.ts` maps to `lib/better_auth/stripe/plugin_factory.rb` plus the public facade in `lib/better_auth/plugins/stripe.rb`.
- [ ] `upstream/packages/stripe/src/error-codes.ts` maps to `lib/better_auth/stripe/error_codes.rb`.
- [ ] `upstream/packages/stripe/src/metadata.ts` maps to `lib/better_auth/stripe/metadata.rb`.
- [ ] `upstream/packages/stripe/src/schema.ts` maps to `lib/better_auth/stripe/schema.rb`.
- [ ] `upstream/packages/stripe/src/utils.ts` maps to `lib/better_auth/stripe/utils.rb`.
- [ ] `upstream/packages/stripe/src/hooks.ts` maps to `lib/better_auth/stripe/hooks.rb`.
- [ ] `upstream/packages/stripe/src/middleware.ts` maps to `lib/better_auth/stripe/middleware.rb` only for server-side reference/session helpers that exist in Ruby.
- [ ] `upstream/packages/stripe/src/routes.ts` maps to `lib/better_auth/stripe/routes/*.rb`.
- [ ] `upstream/packages/stripe/src/types.ts` maps to `lib/better_auth/stripe/types.rb` for Ruby constants and option normalization helpers only.
- [ ] `upstream/packages/stripe/src/client.ts` is not ported because browser/client package exports do not apply to Ruby.
- [ ] `upstream/packages/stripe/src/version.ts` maps to existing `lib/better_auth/stripe/version.rb`.

## Target Ruby File Structure

- [ ] Keep `packages/better_auth-stripe/lib/better_auth/stripe.rb` as the gem loader.
- [ ] Keep `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb` as the compatibility facade for `BetterAuth::Plugins.stripe` and helper delegators.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/client_adapter.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/error_codes.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/metadata.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/schema.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/types.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/utils.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/middleware.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/hooks.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/organization_hooks.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/plugin_factory.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/index.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/upgrade_subscription.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/cancel_subscription.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/restore_subscription.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/list_active_subscriptions.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/create_billing_portal.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/subscription_success.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/cancel_subscription_callback.rb`.
- [ ] Create `packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb`.

## Target Test Structure

- [ ] Keep current broad regression files until the modular files pass.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/client_adapter_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/metadata_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/schema_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/utils_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/hooks_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/organization_hooks_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/cancel_subscription_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/restore_subscription_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/list_active_subscriptions_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/create_billing_portal_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/subscription_success_test.rb`.
- [ ] Create `packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb`.
- [ ] After coverage is moved, reduce `stripe_test.rb` and `stripe_organization_test.rb` to high-level integration tests.

## Ruby Naming Rules

- [ ] Use upstream names for conceptual modules: `Metadata`, `Schema`, `Utils`, `Hooks`, `Routes`.
- [ ] Use snake_case Ruby filenames and method names.
- [ ] Keep public compatibility helpers on `BetterAuth::Plugins` with existing `stripe_` prefixes.
- [ ] Preserve current request compatibility with snake_case and camelCase request keys.
- [ ] Preserve current schema field names as Better Auth schema keys; do not rename database fields during modularization.

## Task 1: Add Module Skeletons And Loader Requires

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe.rb`
- Create: all target module files listed above
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`

- [x] **Step 1: Write the loader require list**

Replace `packages/better_auth-stripe/lib/better_auth/stripe.rb` with this structure:

```ruby
# frozen_string_literal: true

require "better_auth"
require_relative "stripe/version"
require_relative "stripe/client_adapter"
require_relative "stripe/error_codes"
require_relative "stripe/metadata"
require_relative "stripe/schema"
require_relative "stripe/types"
require_relative "stripe/utils"
require_relative "stripe/middleware"
require_relative "stripe/hooks"
require_relative "stripe/organization_hooks"
require_relative "stripe/routes/index"
require_relative "stripe/routes/upgrade_subscription"
require_relative "stripe/routes/cancel_subscription"
require_relative "stripe/routes/restore_subscription"
require_relative "stripe/routes/list_active_subscriptions"
require_relative "stripe/routes/create_billing_portal"
require_relative "stripe/routes/subscription_success"
require_relative "stripe/routes/cancel_subscription_callback"
require_relative "stripe/routes/stripe_webhook"
require_relative "stripe/plugin_factory"
require_relative "plugins/stripe"
```

- [x] **Step 2: Add empty modules with valid Ruby constants**

Each created file starts with `# frozen_string_literal: true` and defines its target module. Example for `metadata.rb`:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Stripe
    module Metadata
      module_function
    end
  end
end
```

Use the same nesting for `Schema`, `Types`, `Utils`, `Middleware`, `Hooks`, `OrganizationHooks`, `PluginFactory`, and each route module under `BetterAuth::Stripe::Routes`.

- [x] **Step 3: Run a syntax-only smoke check**

Run:

```bash
rbenv exec bundle exec ruby -Ipackages/better_auth-stripe/lib -e 'require "better_auth/stripe"; puts BetterAuth::Stripe::VERSION'
```

Expected: prints the gem version and exits with status 0.

- [x] **Step 4: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe.rb packages/better_auth-stripe/lib/better_auth/stripe packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): add modular file skeleton"
```

## Task 2: Extract Client Adapter And Error Codes

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/client_adapter.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/error_codes.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/client_adapter_test.rb`

- [x] **Step 1: Move Stripe SDK adapter classes**

Move these classes verbatim from `plugins/stripe.rb` to `client_adapter.rb`:

```ruby
BetterAuth::Stripe::ClientAdapter
BetterAuth::Stripe::NamespaceAdapter
BetterAuth::Stripe::ResourceAdapter
BetterAuth::Stripe::WebhooksAdapter
```

`client_adapter.rb` must require `stripe` and `securerandom` only if the moved code still needs them in that file.

- [x] **Step 2: Move error constants**

Move `STRIPE_ERROR_CODES` to `BetterAuth::Stripe::ERROR_CODES` in `error_codes.rb`, preserving every key and message currently in `plugins/stripe.rb`.

Also expose:

```ruby
module BetterAuth
  module Plugins
    STRIPE_ERROR_CODES = BetterAuth::Stripe::ERROR_CODES
  end
end
```

inside the facade so existing tests and users can still reference `BetterAuth::Plugins::STRIPE_ERROR_CODES`.

- [x] **Step 3: Add adapter smoke tests**

Create `client_adapter_test.rb` with:

```ruby
# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeClientAdapterTest < Minitest::Test
  def test_webhooks_adapter_supports_sync_and_async_construct_event
    adapter = BetterAuth::Stripe::WebhooksAdapter.new

    assert_respond_to adapter, :construct_event
    assert_respond_to adapter, :construct_event_async
  end

  def test_error_codes_are_exposed_through_compatibility_constant
    assert_equal BetterAuth::Stripe::ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND"),
      BetterAuth::Plugins::STRIPE_ERROR_CODES.fetch("SUBSCRIPTION_NOT_FOUND")
  end
end
```

- [x] **Step 4: Run focused tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/client_adapter_test.rb
```

Expected: 2 runs, 0 failures.

- [x] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/client_adapter.rb packages/better_auth-stripe/lib/better_auth/stripe/error_codes.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/client_adapter_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract client adapter and errors"
```

## Task 3: Extract Metadata Helpers

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/metadata.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/metadata_test.rb`

- [x] **Step 1: Move metadata implementation**

Move these methods from `plugins/stripe.rb` to `BetterAuth::Stripe::Metadata`:

```ruby
stripe_metadata
stripe_customer_metadata_set
stripe_customer_metadata_get
stripe_subscription_metadata_set
stripe_subscription_metadata_get
stripe_metadata_key
stripe_metadata_fetch
stripe_deep_merge
stripe_stringify_keys
```

Rename the module methods to Ruby-local names:

```ruby
merge
customer_set
customer_get
subscription_set
subscription_get
metadata_key
metadata_fetch
deep_merge
stringify_keys
```

Keep facade delegators on `BetterAuth::Plugins`:

```ruby
def stripe_customer_metadata_set(internal_fields, *user_metadata)
  BetterAuth::Stripe::Metadata.customer_set(internal_fields, *user_metadata)
end

def stripe_customer_metadata_get(metadata)
  BetterAuth::Stripe::Metadata.customer_get(metadata)
end

def stripe_subscription_metadata_set(internal_fields, *user_metadata)
  BetterAuth::Stripe::Metadata.subscription_set(internal_fields, *user_metadata)
end

def stripe_subscription_metadata_get(metadata)
  BetterAuth::Stripe::Metadata.subscription_get(metadata)
end
```

- [x] **Step 2: Preserve unsafe key filtering**

Move `STRIPE_UNSAFE_METADATA_KEYS` to:

```ruby
module BetterAuth
  module Stripe
    module Metadata
      UNSAFE_KEYS = %w[__proto__ constructor prototype].freeze
    end
  end
end
```

- [x] **Step 3: Add metadata tests mirroring upstream**

Create `metadata_test.rb` with tests that cover:

```ruby
def test_customer_metadata_preserves_internal_fields_and_custom_values
def test_subscription_metadata_preserves_internal_fields_and_custom_values
def test_metadata_drops_unsafe_keys
def test_metadata_accepts_symbol_and_string_keys
```

Use the assertions currently in `stripe_test.rb` for metadata helpers and add this symbol/string case:

```ruby
metadata = BetterAuth::Stripe::Metadata.customer_set(
  {userId: "u1", customerType: "user"},
  {"customField" => "value", organization_id: "ignored"}
)

assert_equal "u1", metadata.fetch("userId")
assert_equal "user", metadata.fetch("customerType")
assert_equal "value", metadata.fetch("customField")
```

- [x] **Step 4: Run metadata tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/metadata_test.rb
```

Expected: 4 runs, 0 failures.

- [x] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/metadata.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/metadata_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract metadata helpers"
```

## Task 4: Extract Schema

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/schema.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/schema_test.rb`

- [x] **Step 1: Move schema implementation**

Move `stripe_schema(config)` to `BetterAuth::Stripe::Schema.schema(config)`.

Keep this facade delegator:

```ruby
def stripe_schema(config)
  BetterAuth::Stripe::Schema.schema(config)
end
```

- [x] **Step 2: Add custom schema merge parity check**

Upstream `schema.ts` merges `options.schema`. If Ruby does not currently support `config[:schema]`, add support in `BetterAuth::Stripe::Schema.schema` by deep merging `config[:schema]` into the generated schema, with the upstream adaptation that `subscription` custom schema is ignored when subscriptions are disabled.

Ruby adaptation: `BetterAuth::Stripe::Schema.deep_merge_schema` is used instead of `BetterAuth::Stripe::Metadata.deep_merge` because metadata deep merge normalizes camelCase keys to snake_case, while raw plugin schema still needs upstream-style camelCase field names before Better Auth normalizes schema storage keys.

- [x] **Step 3: Add schema tests**

Create `schema_test.rb` with:

```ruby
# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeSchemaTest < Minitest::Test
  def test_base_schema_includes_user_stripe_customer_id
    schema = BetterAuth::Stripe::Schema.schema({})

    assert_equal({type: "string", required: false}, schema.fetch(:user).fetch(:fields).fetch(:stripeCustomerId))
    refute schema.key?(:subscription)
  end

  def test_subscription_schema_includes_upstream_fields
    schema = BetterAuth::Stripe::Schema.schema(subscription: {enabled: true, plans: []})
    fields = schema.fetch(:subscription).fetch(:fields)

    assert_equal({type: "string", required: false}, fields.fetch(:billingInterval))
    assert_equal({type: "string", required: false}, fields.fetch(:stripeScheduleId))
  end

  def test_organization_schema_is_conditional
    schema = BetterAuth::Stripe::Schema.schema(organization: {enabled: true})

    assert_equal({type: "string", required: false}, schema.fetch(:organization).fetch(:fields).fetch(:stripeCustomerId))
  end
end
```

- [x] **Step 4: Run schema tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/schema_test.rb
```

Expected: 3 runs, 0 failures.

- [x] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/schema.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/schema_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract schema"
```

## Task 5: Extract Utilities And Types

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/utils.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/types.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/utils_test.rb`

- [x] **Step 1: Move option and plan helpers**

Move these methods to `BetterAuth::Stripe::Utils`:

```ruby
stripe_subscription_options
stripe_plans
stripe_plan_by_name
stripe_plan_by_price_info
stripe_price_id
stripe_resolve_lookup
stripe_metered_price?
stripe_resolve_stripe_price
stripe_resolve_plan_item
stripe_resolve_quantity
stripe_subscription_state
stripe_schedule_id
```

Rename them without `stripe_` inside the module and keep `BetterAuth::Plugins` delegators for any helper currently used by tests.

- [x] **Step 2: Move generic helpers**

Move these methods to `BetterAuth::Stripe::Utils`:

```ruby
stripe_id
stripe_fetch
stripe_time
stripe_active_or_trialing?
stripe_pending_cancel?
stripe_stripe_pending_cancel?
stripe_subscription_item
stripe_line_item
stripe_checkout_line_items
stripe_plan_line_items
stripe_direct_subscription_update?
stripe_redirect?
stripe_url
stripe_escape_search
```

- [x] **Step 3: Add type constants for documented option values**

In `types.rb`, add:

```ruby
module BetterAuth
  module Stripe
    module Types
      CUSTOMER_TYPES = %w[user organization].freeze
      AUTHORIZE_REFERENCE_ACTIONS = %w[
        upgrade-subscription
        cancel-subscription
        restore-subscription
        billing-portal
        list-subscriptions
      ].freeze
    end
  end
end
```

- [x] **Step 4: Add utils tests mirroring upstream `utils.test.ts`**

Create `utils_test.rb` with:

```ruby
# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeUtilsTest < Minitest::Test
  def test_escape_search_value_matches_upstream
    assert_equal "foo\\\"bar", BetterAuth::Stripe::Utils.escape_search("foo\"bar")
    assert_equal "foo\\\\bar", BetterAuth::Stripe::Utils.escape_search("foo\\bar")
  end

  def test_active_or_trialing_matches_upstream_statuses
    assert BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "active"})
    assert BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "trialing"})
    refute BetterAuth::Stripe::Utils.active_or_trialing?({"status" => "canceled"})
  end

  def test_pending_cancel_checks_database_subscription
    assert BetterAuth::Stripe::Utils.pending_cancel?({"cancelAtPeriodEnd" => true})
    assert BetterAuth::Stripe::Utils.pending_cancel?({"stripeScheduleId" => "sched_123"})
    refute BetterAuth::Stripe::Utils.pending_cancel?({})
  end
end
```

- [x] **Step 5: Run utils tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/utils_test.rb
```

Expected: 3 runs, 0 failures.

- [x] **Step 6: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/utils.rb packages/better_auth-stripe/lib/better_auth/stripe/types.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/utils_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract utility helpers"
```

## Task 6: Extract Middleware And Authorization Helpers

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/middleware.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb`

- [x] **Step 1: Move reference and customer type helpers**

Move these methods to `BetterAuth::Stripe::Middleware`:

```ruby
stripe_reference_id!
stripe_authorize_reference!
stripe_customer_type!
stripe_reference_by_customer
```

Keep facade delegators for existing test access.

- [x] **Step 2: Preserve Ruby request key compatibility**

The module methods must accept both snake_case and camelCase inputs through the existing normalized body behavior. Preserve accepted keys:

```ruby
:reference_id
:referenceId
:customer_type
:customerType
:subscription_id
:subscriptionId
```

- [x] **Step 3: Add route-level authorization tests**

Ruby adaptation: added direct module coverage in `packages/better_auth-stripe/test/better_auth/stripe/middleware_test.rb` for `customer_type!`, `reference_id!`, and `authorize_reference!`. The integration tests below remain in `stripe_test.rb` until the upgrade route is extracted, because moving them before route extraction would duplicate broad route setup without improving behavior isolation.

Move these existing tests from `stripe_test.rb` into `routes/upgrade_subscription_test.rb` during Task 9:

```ruby
test_upgrade_rejects_invalid_customer_type
test_reference_authorization_blocks_cross_reference_operations
test_cross_user_subscription_id_operations_reject_upgrade_cancel_and_restore
test_user_reference_authorization_branches_match_upstream
```

Keep the original tests until the moved tests pass, then remove duplicates from `stripe_test.rb`.

- [x] **Step 4: Run moved tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/middleware_test.rb
```

Expected: middleware authorization tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/middleware.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract reference middleware"
```

## Task 7: Extract Webhook Hooks

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/hooks.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/hooks_test.rb`

- [ ] **Step 1: Move webhook event handlers**

Move these methods to `BetterAuth::Stripe::Hooks`:

```ruby
stripe_handle_event
stripe_on_checkout_completed
stripe_on_subscription_created
stripe_on_subscription_updated
stripe_on_subscription_deleted
```

Rename them inside the module:

```ruby
handle_event
on_checkout_completed
on_subscription_created
on_subscription_updated
on_subscription_deleted
```

- [ ] **Step 2: Wire dependencies through module calls**

Inside `Hooks`, call:

```ruby
BetterAuth::Stripe::Utils
BetterAuth::Stripe::Metadata
BetterAuth::Stripe::ERROR_CODES
```

instead of using methods on `BetterAuth::Plugins`.

- [ ] **Step 3: Add hook tests**

Move these existing tests from `stripe_test.rb` into `hooks_test.rb`:

```ruby
test_webhook_verifies_signature_and_updates_subscription
test_webhook_creates_subscription_from_created_event_metadata
test_webhook_event_matrix_and_callbacks
test_subscription_webhook_syncs_interval_schedule_and_clears_stale_cancel_fields
test_subscription_update_resolves_plan_item_from_multi_item_subscription
test_subscription_update_invokes_trial_end_and_expired_callbacks
test_created_webhook_skips_duplicates_missing_reference_and_unknown_plan
```

- [ ] **Step 4: Run hook tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/hooks_test.rb
```

Expected: all moved hook tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/hooks.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/hooks_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract webhook hooks"
```

## Task 8: Extract Organization Hooks

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/organization_hooks.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/organization_hooks_test.rb`

- [ ] **Step 1: Move organization hook factory**

Move these methods to `BetterAuth::Stripe::OrganizationHooks`:

```ruby
stripe_organization_hooks
stripe_sync_organization_seats
```

Expose:

```ruby
def self.hooks(config)
def self.sync_seats(config, data, ctx)
```

- [ ] **Step 2: Preserve upstream hook names through Ruby adapter names**

The returned hash must continue to use current Ruby organization hook keys:

```ruby
:after_update_organization
:before_delete_organization
:after_add_member
:after_remove_member
:after_accept_invitation
```

Document in this plan that upstream camelCase hook names are adapted to Ruby snake_case because the Ruby organization plugin expects snake_case.

- [ ] **Step 3: Add organization hook tests**

Move these existing tests from `stripe_organization_test.rb` into `organization_hooks_test.rb`:

```ruby
test_organization_member_removal_syncs_seat_quantity
test_accepting_invitation_syncs_seat_quantity
test_organization_webhooks_and_delete_guard
test_organization_name_sync_and_deletion_without_active_subscription
```

- [ ] **Step 4: Run organization hook tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/organization_hooks_test.rb
```

Expected: all moved organization hook tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/organization_hooks.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/organization_hooks_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract organization hooks"
```

## Task 9: Extract Route Index And Subscription Upgrade Route

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/index.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/upgrade_subscription.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb`

- [ ] **Step 1: Move route registry**

Move `stripe_endpoints(config)` to `BetterAuth::Stripe::Routes.endpoints(config)`.

The endpoint hash must keep current Ruby API names:

```ruby
{
  stripe_webhook: BetterAuth::Stripe::Routes::StripeWebhook.endpoint(config),
  upgrade_subscription: BetterAuth::Stripe::Routes::UpgradeSubscription.endpoint(config),
  cancel_subscription_callback: BetterAuth::Stripe::Routes::CancelSubscriptionCallback.endpoint(config),
  cancel_subscription: BetterAuth::Stripe::Routes::CancelSubscription.endpoint(config),
  restore_subscription: BetterAuth::Stripe::Routes::RestoreSubscription.endpoint(config),
  list_active_subscriptions: BetterAuth::Stripe::Routes::ListActiveSubscriptions.endpoint(config),
  subscription_success: BetterAuth::Stripe::Routes::SubscriptionSuccess.endpoint(config),
  create_billing_portal: BetterAuth::Stripe::Routes::CreateBillingPortal.endpoint(config)
}
```

Only include subscription endpoints when `config.dig(:subscription, :enabled)` is truthy.

- [ ] **Step 2: Move upgrade endpoint**

Move `stripe_upgrade_subscription_endpoint(config)` to:

```ruby
module BetterAuth
  module Stripe
    module Routes
      module UpgradeSubscription
        module_function

        def endpoint(config)
          BetterAuth::Endpoint.new(path: "/subscription/upgrade", method: "POST", &handler(config))
        end

        def handler(config)
          lambda do |ctx|
            session = BetterAuth::Routes.current_session(ctx)
            body = BetterAuth::Plugins.normalize_hash(ctx.body)
            subscription_options = BetterAuth::Stripe::Utils.subscription_options(config)
            customer_type = BetterAuth::Stripe::Middleware.customer_type!(body)
            reference_id = BetterAuth::Stripe::Middleware.reference_id!(ctx, session, customer_type, body[:reference_id], config)

            BetterAuth::Stripe::Middleware.authorize_reference!(
              ctx,
              session,
              reference_id,
              "upgrade-subscription",
              customer_type,
              subscription_options,
              explicit: body.key?(:reference_id)
            )

            BetterAuth::Stripe::Routes::UpgradeSubscription.checkout_or_update(ctx, config, session, body, customer_type, reference_id, subscription_options)
          end
        end
      end
    end
  end
end
```

`checkout_or_update` is the rest of the current `stripe_upgrade_subscription_endpoint` control flow extracted as a private module method in the same file. It keeps the current branches for email verification, plan lookup, existing subscription lookup, customer creation, lookup-key resolution, checkout creation, direct subscription updates, scheduled plan changes, metadata protection, and redirect response shaping.

Replace calls to old helper methods with module calls:

```ruby
BetterAuth::Stripe::Utils
BetterAuth::Stripe::Middleware
BetterAuth::Stripe::Metadata
```

- [ ] **Step 3: Add route tests**

Move these tests from `stripe_test.rb` into `routes/upgrade_subscription_test.rb`:

```ruby
test_creates_customer_on_sign_up_and_subscription_checkout
test_upgrade_falls_back_to_customer_list_when_search_unavailable
test_checkout_session_params_merge_options_metadata_and_lookup_keys
test_upgrade_rejects_plan_when_price_id_cannot_be_resolved
test_metered_checkout_line_item_omits_quantity
test_schedules_plan_change_at_period_end_and_restore_releases_schedule
test_upgrade_protects_internal_metadata_applies_seats_and_prevents_trial_abuse
test_schedule_release_and_line_item_replacement_parity
test_metered_prices_omit_quantity_for_direct_and_scheduled_upgrades_but_licensed_keeps_quantity
```

- [ ] **Step 4: Run upgrade route tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/upgrade_subscription_test.rb
```

Expected: all moved upgrade route tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/routes/index.rb packages/better_auth-stripe/lib/better_auth/stripe/routes/upgrade_subscription.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/routes/upgrade_subscription_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract upgrade route"
```

## Task 10: Extract Remaining Subscription Routes

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: route files under `packages/better_auth-stripe/lib/better_auth/stripe/routes/`
- Test: route tests under `packages/better_auth-stripe/test/better_auth/stripe/routes/`

- [ ] **Step 1: Move cancel route**

Move `stripe_cancel_subscription_endpoint(config)` to `BetterAuth::Stripe::Routes::CancelSubscription.endpoint(config)`.

Move these tests:

```ruby
test_lists_cancels_restores_and_opens_billing_portal
test_cancel_fallback_syncs_when_stripe_reports_already_canceled
```

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/cancel_subscription_test.rb
```

- [ ] **Step 2: Move restore route**

Move `stripe_restore_subscription_endpoint(config)` to `BetterAuth::Stripe::Routes::RestoreSubscription.endpoint(config)`.

Move these tests:

```ruby
test_restore_rejects_when_subscription_has_no_pending_cancel_or_schedule
test_lists_cancels_restores_and_opens_billing_portal
```

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/restore_subscription_test.rb
```

- [ ] **Step 3: Move list route**

Move `stripe_list_subscriptions_endpoint(config)` to `BetterAuth::Stripe::Routes::ListActiveSubscriptions.endpoint(config)`.

Move these tests:

```ruby
test_list_active_subscriptions_returns_annual_price_for_yearly_subscription
test_flexible_limits_types_are_preserved_in_subscription_list
```

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/list_active_subscriptions_test.rb
```

- [ ] **Step 4: Move billing portal route**

Move `stripe_billing_portal_endpoint(config)` to `BetterAuth::Stripe::Routes::CreateBillingPortal.endpoint(config)`.

Move these tests:

```ruby
test_lists_cancels_restores_and_opens_billing_portal
test_metered_billing_portal_update_item_omits_quantity
test_custom_reference_billing_portal_and_upgrade_do_not_mutate_personal_subscription
```

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/create_billing_portal_test.rb
```

- [ ] **Step 5: Move success and cancel callback routes**

Move:

```ruby
stripe_success_endpoint(config)
stripe_cancel_callback_endpoint(config)
```

to:

```ruby
BetterAuth::Stripe::Routes::SubscriptionSuccess.endpoint(config)
BetterAuth::Stripe::Routes::CancelSubscriptionCallback.endpoint(config)
```

Move these tests:

```ruby
test_subscription_success_cancel_callback_restore_and_webhook_errors
test_subscription_success_uses_checkout_session_metadata_and_replaces_placeholder
test_subscription_success_redirect_branches_and_checkout_retrieve_failure
```

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/subscription_success_test.rb
```

- [ ] **Step 6: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/routes packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/routes packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract subscription routes"
```

## Task 11: Extract Webhook Route

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb`
- Test: `packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb`

- [ ] **Step 1: Move webhook endpoint**

Move `stripe_webhook_endpoint(config)` to `BetterAuth::Stripe::Routes::StripeWebhook.endpoint(config)`.

Call:

```ruby
BetterAuth::Stripe::Hooks.handle_event(ctx, event)
```

after event construction succeeds.

- [ ] **Step 2: Preserve webhook construction behavior**

The endpoint must preserve all current branches:

```ruby
missing stripe-signature header -> STRIPE_SIGNATURE_NOT_FOUND
missing webhook secret -> STRIPE_WEBHOOK_SECRET_NOT_FOUND
construct_event_async when available
construct_event fallback when async method is unavailable
nil event -> FAILED_TO_CONSTRUCT_STRIPE_EVENT
handler exception -> STRIPE_WEBHOOK_ERROR
```

- [ ] **Step 3: Move webhook endpoint tests**

Move these tests from `stripe_test.rb`:

```ruby
test_webhook_prefers_construct_event_async_when_available
test_webhook_processing_errors_return_webhook_error
test_webhook_rejects_missing_secret_null_event_and_supports_sync_construct_event
```

- [ ] **Step 4: Run webhook route tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/stripe/routes/stripe_webhook_test.rb
```

Expected: all moved webhook route tests pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/routes/stripe_webhook.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/stripe/routes/stripe_webhook_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract webhook route"
```

## Task 12: Extract Plugin Factory And Facade

**Files:**
- Modify: `packages/better_auth-stripe/lib/better_auth/stripe/plugin_factory.rb`
- Modify: `packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb`
- Test: `packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb`

- [ ] **Step 1: Move plugin assembly**

Move `stripe(options = {})` to:

```ruby
module BetterAuth
  module Stripe
    module PluginFactory
      module_function

      def build(options = {})
        config = BetterAuth::Plugins.normalize_hash(options)
        Plugin.new(
          id: "stripe",
          version: BetterAuth::Stripe::VERSION,
          init: ->(ctx) { {context: {schema: Schema.auth_tables(ctx.options)}} },
          schema: BetterAuth::Stripe::Schema.schema(config),
          endpoints: BetterAuth::Stripe::Routes.endpoints(config),
          error_codes: BetterAuth::Stripe::ERROR_CODES,
          options: config.merge(
            database_hooks: database_hooks(config),
            organization_hooks: BetterAuth::Stripe::OrganizationHooks.hooks(config)
          )
        )
      end
    end
  end
end
```

Use existing Ruby `Schema.auth_tables(ctx.options)` behavior exactly as the current plugin does.

- [ ] **Step 2: Move database hooks**

Move `stripe_database_hooks(config)` into `BetterAuth::Stripe::PluginFactory.database_hooks(config)`.

Keep behavior:

```ruby
return {} unless config[:create_customer_on_sign_up]
```

and preserve the current tolerant rescue behavior on sign-up and email sync.

- [ ] **Step 3: Reduce public facade**

`packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb` should contain:

```ruby
# frozen_string_literal: true

module BetterAuth
  module Plugins
    singleton_class.remove_method(:stripe) if singleton_class.method_defined?(:stripe)
    remove_method(:stripe) if method_defined?(:stripe) || private_method_defined?(:stripe)

    STRIPE_ERROR_CODES = BetterAuth::Stripe::ERROR_CODES

    module_function

    def stripe(options = {})
      BetterAuth::Stripe::PluginFactory.build(options)
    end

    def stripe_schema(config)
      BetterAuth::Stripe::Schema.schema(config)
    end

    def stripe_customer_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.customer_set(internal_fields, *user_metadata)
    end

    def stripe_customer_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.customer_get(metadata)
    end

    def stripe_subscription_metadata_set(internal_fields, *user_metadata)
      BetterAuth::Stripe::Metadata.subscription_set(internal_fields, *user_metadata)
    end

    def stripe_subscription_metadata_get(metadata)
      BetterAuth::Stripe::Metadata.subscription_get(metadata)
    end
  end
end
```

- [ ] **Step 4: Run broad existing tests**

Run:

```bash
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/plugins/stripe_test.rb
rbenv exec bundle exec ruby -Itest -Ilib test/better_auth/plugins/stripe_organization_test.rb
```

Expected: both legacy regression files pass.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib/better_auth/stripe/plugin_factory.rb packages/better_auth-stripe/lib/better_auth/plugins/stripe.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): extract plugin factory"
```

## Task 13: Build Upstream Parity Matrix

**Files:**
- Modify: `.docs/plans/2026-05-01-2350--modularize-stripe-plugin.md`
- Optional create: `.docs/features/stripe-upstream-parity.md` if the checklist grows too large for this plan

- [ ] **Step 1: Count upstream and Ruby tests**

Run:

```bash
rg -n "\\b(it|test)\\(" upstream/packages/stripe/test packages/better_auth-stripe/test
```

Record counts in this plan under `Parity Matrix`.

- [ ] **Step 2: Classify upstream test cases**

For each upstream test file, add one checklist item per behavior with one status:

```markdown
- [ ] Covered in Ruby: `test_name_here`
- [ ] Missing Ruby coverage: `upstream behavior here`
- [ ] Intentionally not ported: browser/client-only behavior here
- [ ] Ruby adaptation: upstream async/browser behavior handled synchronously here
```

- [ ] **Step 3: Classify upstream source exports**

For every export found by:

```bash
rg -n "^export|^async function|^function|^const .*Schema|^export const|^export function" upstream/packages/stripe/src
```

add a matching Ruby module/method or an intentional-not-ported note.

- [ ] **Step 4: Commit**

```bash
git add .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md .docs/features/stripe-upstream-parity.md
git commit -m "docs(stripe): add upstream parity matrix"
```

## Task 14: Final Verification And Cleanup

**Files:**
- Modify: only files touched by this plan

- [ ] **Step 1: Run package test suite**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec rake test
```

Expected: all `better_auth-stripe` tests pass.

- [ ] **Step 2: Run style check**

Run:

```bash
cd packages/better_auth-stripe
rbenv exec bundle exec standardrb
```

Expected: exits with status 0.

- [ ] **Step 3: Run root-level smoke if package paths require it**

Run from repo root:

```bash
rbenv exec bundle exec ruby -Ipackages/better_auth-stripe/lib -e 'require "better_auth/stripe"; plugin = BetterAuth::Plugins.stripe(subscription: {enabled: true, plans: []}); puts plugin.id'
```

Expected: prints `stripe`.

- [ ] **Step 4: Remove duplicate tests only after moved tests pass**

Delete duplicated assertions from:

```ruby
packages/better_auth-stripe/test/better_auth/plugins/stripe_test.rb
packages/better_auth-stripe/test/better_auth/plugins/stripe_organization_test.rb
```

Keep at least these high-level integration tests in the legacy files:

```ruby
test_creates_customer_on_sign_up_and_subscription_checkout
test_lists_cancels_restores_and_opens_billing_portal
test_webhook_verifies_signature_and_updates_subscription
test_organization_subscription_flow_uses_active_org_and_authorize_reference
```

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-stripe/lib packages/better_auth-stripe/test .docs/plans/2026-05-01-2350--modularize-stripe-plugin.md
git commit -m "refactor(stripe): complete upstream-style modularization"
```

## Parity Matrix

Initial inventory from this planning pass:

- [x] Upstream Stripe tests currently detected: 150 test cases.
- [x] Ruby Stripe tests currently detected: 62 Minitest cases.
- [x] Upstream source export/function declarations currently detected: 57 lines.
- [ ] Task 13 must replace this count-level inventory with behavior-by-behavior mapping.

### Upstream Source Files

- [ ] `src/index.ts`
- [ ] `src/error-codes.ts`
- [ ] `src/metadata.ts`
- [ ] `src/schema.ts`
- [ ] `src/utils.ts`
- [ ] `src/hooks.ts`
- [ ] `src/middleware.ts`
- [ ] `src/routes.ts`
- [ ] `src/types.ts`
- [ ] `src/client.ts` intentionally not ported for Ruby browser-client reasons.
- [ ] `src/version.ts`

### Upstream Test Files

- [ ] `test/metadata.test.ts`
- [ ] `test/utils.test.ts`
- [ ] `test/stripe.test.ts`
- [ ] `test/stripe-organization.test.ts`
- [ ] `test/seat-based-billing.test.ts`

## Ruby Adaptations Already Expected

- [ ] Upstream browser client exports from `client.ts` are not ported.
- [ ] TypeScript-only declarations from `types.ts` are represented as Ruby constants, option normalization, and tests, not as runtime type objects.
- [ ] zod body/query schemas in `routes.ts` are represented by Ruby endpoint body normalization and explicit `APIError` branches.
- [ ] Async Stripe calls are synchronous through the Stripe Ruby SDK adapter.
- [ ] Upstream camelCase organization hook names are adapted to Ruby snake_case hook names.
- [ ] Keep both snake_case and camelCase request inputs where the current Ruby plugin already supports them.
- [x] Schema custom merge uses a schema-specific deep merge to preserve raw camelCase field keys until Better Auth schema normalization runs.

## Self-Review

- [x] Spec coverage: plan covers modularization, upstream 1:1 file mapping, Ruby-only exclusions, tests, and parity inventory.
- [x] Placeholder scan: no `TBD`, `TODO`, or open-ended implementation placeholders are intentionally left.
- [x] Type consistency: target modules consistently use `BetterAuth::Stripe::*` and facade delegators consistently live on `BetterAuth::Plugins`.
- [x] Testing strategy: each extraction task has focused tests plus final package test and style verification.
