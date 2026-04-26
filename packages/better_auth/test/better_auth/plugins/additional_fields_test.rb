# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPluginsAdditionalFieldsTest < Minitest::Test
  SECRET = "phase-seven-secret-with-enough-entropy-123"

  def test_additional_fields_plugin_merges_user_and_session_schema
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.additional_fields(
          user: {
            favoriteColor: {type: "string", required: false, default_value: "blue"},
            nickname: {type: "string", required: false}
          },
          session: {
            deviceName: {type: "string", required: false, default_value: "web"}
          }
        )
      ]
    )

    cookie = sign_up_cookie(auth, email: "fields@example.com", favorite_color: "green")
    session = auth.api.get_session(headers: {"cookie" => cookie})

    assert_equal "green", session[:user]["favoriteColor"]
    assert_equal "web", session[:session]["deviceName"]

    auth.api.update_user(headers: {"cookie" => cookie}, body: {nickname: "Fieldy"})
    updated = auth.api.get_session(headers: {"cookie" => cookie}, query: {disableCookieCache: true})

    assert_equal "Fieldy", updated[:user]["nickname"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:, favorite_color:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Fields User", favoriteColor: favorite_color},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
