# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyOrgAuthorizationTest < Minitest::Test
  def test_permission_constant_matches_upstream_actions
    assert_equal %w[create read update delete], BetterAuth::APIKey::OrgAuthorization::PERMISSIONS.fetch(:apiKey)
  end
end
