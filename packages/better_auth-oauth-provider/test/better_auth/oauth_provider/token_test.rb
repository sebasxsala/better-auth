# frozen_string_literal: true

require_relative "../../test_helper"

class OAuthProviderTokenTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_token_endpoint_rejects_unsupported_grant_type
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "password",
          client_id: client[:client_id],
          client_secret: client[:client_secret]
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/unsupported_grant_type/, error.message)
  end
end
