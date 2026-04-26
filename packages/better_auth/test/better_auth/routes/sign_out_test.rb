# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthRoutesSignOutTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_sign_out_without_session_still_returns_success_and_clears_cookies
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)

    status, headers, body = auth.api.sign_out(as_response: true)

    assert_equal 200, status
    assert_equal({"success" => true}, JSON.parse(body.join))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert_includes headers.fetch("set-cookie"), "Max-Age=0"
  end
end
