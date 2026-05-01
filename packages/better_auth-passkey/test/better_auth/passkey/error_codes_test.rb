# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPasskeyErrorCodesTest < Minitest::Test
  EXPECTED_ERROR_CODES = {
    "CHALLENGE_NOT_FOUND" => "Challenge not found",
    "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY" => "You are not allowed to register this passkey",
    "FAILED_TO_VERIFY_REGISTRATION" => "Failed to verify registration",
    "PASSKEY_NOT_FOUND" => "Passkey not found",
    "AUTHENTICATION_FAILED" => "Authentication failed",
    "UNABLE_TO_CREATE_SESSION" => "Unable to create session",
    "FAILED_TO_UPDATE_PASSKEY" => "Failed to update passkey",
    "PREVIOUSLY_REGISTERED" => "Previously registered",
    "REGISTRATION_CANCELLED" => "Registration cancelled",
    "AUTH_CANCELLED" => "Auth cancelled",
    "UNKNOWN_ERROR" => "Unknown error",
    "SESSION_REQUIRED" => "Passkey registration requires an authenticated session",
    "RESOLVE_USER_REQUIRED" => "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
    "RESOLVED_USER_INVALID" => "Resolved user is invalid"
  }.freeze

  def test_error_codes_match_upstream_messages
    assert_equal EXPECTED_ERROR_CODES, BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES
  end

  def test_legacy_plugin_constant_points_to_same_error_codes
    assert_same BetterAuth::Passkey::ErrorCodes::PASSKEY_ERROR_CODES, BetterAuth::Plugins::PASSKEY_ERROR_CODES
  end
end
