# frozen_string_literal: true

require_relative "../../../test_helper"

class OAuthProviderUtilsTimestampsTest < Minitest::Test
  Utils = BetterAuth::Plugins::OAuthProvider::Utils

  def test_normalize_timestamp_value_accepts_epoch_millis_strings
    value = Utils.normalize_timestamp_value("1774295570569.0")

    assert_equal 1_774_295_570, value.to_i
  end

  def test_resolve_session_auth_time_uses_created_at_only
    resolved = Utils.resolve_session_auth_time({"session" => {"created_at" => 1_774_295_569}})

    assert_equal 1_774_295_569, resolved.to_i
    assert_nil Utils.resolve_session_auth_time({"session" => {"updated_at" => 1_774_295_569}})
  end
end
