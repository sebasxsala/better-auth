# frozen_string_literal: true

require "json"
require "uri"
require_relative "../../test_helper"

class BetterAuthRoutesSocialTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_sign_in_social_with_id_token_creates_user_account_and_session
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-1",
                email: "social@example.com",
                name: "Social User",
                image: "https://example.com/avatar.png",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    status, headers, body = auth.api.sign_in_social(
      body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}},
      as_response: true
    )
    data = JSON.parse(body.join)

    assert_equal 200, status
    assert_equal false, data.fetch("redirect")
    assert_equal "social@example.com", data.fetch("user").fetch("email")
    assert_match(/\A[0-9a-f]{32}\z/, data.fetch("token"))
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    account = auth.context.internal_adapter.find_accounts(data.fetch("user").fetch("id")).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-1", account["accountId"]
    assert_equal "access-token", account["accessToken"]
  end

  def test_sign_in_social_returns_authorization_url_and_callback_completes_session
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}&redirect_uri=#{URI.encode_www_form_component(data[:redirectURI])}"
          end,
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access", refreshToken: "oauth-refresh", scopes: ["user"]} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-2",
                email: "callback@example.com",
                name: "Callback User",
                emailVerified: true
              }
            }
          }
        }
      }
    )

    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/app", headers["location"]
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("callback@example.com")[:user]
    account = auth.context.internal_adapter.find_accounts(user["id"]).find { |entry| entry["providerId"] == "github" }
    assert_equal "oauth-refresh", account["refreshToken"]
    assert_equal "user", account["scope"]
  end

  def test_link_social_with_id_token_links_account_to_current_user
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-linked",
                email: "link@example.com",
                name: "Linked",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    result = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", idToken: {token: "id-token", accessToken: "access-token"}}
    )

    assert_equal({url: "", status: true, redirect: false}, result)
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-linked", account["accountId"]
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Social User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
