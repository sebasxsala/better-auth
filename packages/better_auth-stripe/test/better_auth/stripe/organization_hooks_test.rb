# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthStripeOrganizationHooksTest < Minitest::Test
  def test_hooks_returns_empty_hash_when_organization_is_disabled
    assert_equal({}, BetterAuth::Stripe::OrganizationHooks.hooks({}))
  end

  def test_hooks_exposes_organization_hook_names_when_enabled
    hooks = BetterAuth::Stripe::OrganizationHooks.hooks(organization: {enabled: true}, subscription: {enabled: true, plans: []})

    assert_respond_to BetterAuth::Stripe::OrganizationHooks, :sync_seats
    assert_includes hooks.keys, :after_update_organization
    assert_includes hooks.keys, :before_delete_organization
    assert_includes hooks.keys, :after_add_member
    assert_includes hooks.keys, :after_remove_member
    assert_includes hooks.keys, :after_accept_invitation
  end
end
