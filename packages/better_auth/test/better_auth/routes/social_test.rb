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
    issued_code_verifier = nil
    callback_code_verifier = nil
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            issued_code_verifier = data[:codeVerifier]
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}&redirect_uri=#{URI.encode_www_form_component(data[:redirectURI])}"
          end,
          validate_authorization_code: lambda do |data|
            callback_code_verifier = data[:codeVerifier]
            {accessToken: "oauth-access", refreshToken: "oauth-refresh", scopes: ["user"]}
          end,
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
    assert_match(/\A[0-9a-f]{32}\z/, issued_code_verifier)
    assert_equal issued_code_verifier, callback_code_verifier
  end

  def test_callback_post_redirects_to_get_with_merged_body_and_query
    called = false
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { called = true },
          get_user_info: ->(_tokens) { raise "unexpected user info call" }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {state: "query-state"},
      body: {code: "code", state: state},
      method: "POST",
      as_response: true
    )

    assert_equal 302, status
    location = headers.fetch("location")
    assert_match(%r{\Ahttp://localhost:3000/api/auth/callback/github\?}, location)
    params = Rack::Utils.parse_query(URI.parse(location).query)
    assert_equal "code", params.fetch("code")
    assert_equal state, params.fetch("state")
    refute called
  end

  def test_sign_in_social_rejects_implicit_signup_when_provider_disables_it
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          disableImplicitSignUp: true,
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-disabled-signup",
                email: "disabled-signup@example.com",
                name: "Disabled Signup",
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
    assert_includes headers.fetch("location"), "error=signup_disabled"
    assert_nil auth.context.internal_adapter.find_user_by_email("disabled-signup@example.com")
  end

  def test_sign_in_social_allows_requested_signup_when_implicit_signup_is_disabled
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          disableImplicitSignUp: true,
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "oauth-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-requested-signup",
                email: "requested-signup@example.com",
                name: "Requested Signup",
                emailVerified: true
              }
            }
          }
        }
      }
    )
    response = auth.api.sign_in_social(body: {provider: "github", callbackURL: "/app", requestSignUp: true, disableRedirect: true})
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/app", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("requested-signup@example.com")
  end

  def test_sign_in_social_rejects_unverified_implicit_linking_from_untrusted_provider
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-unverified-link",
                email: "unverified-link@example.com",
                name: "Unverified Link",
                emailVerified: false
              }
            }
          }
        }
      }
    )
    sign_up_cookie(auth, email: "unverified-link@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_social(body: {provider: "github", idToken: {token: "id-token"}})
    end

    assert_equal "account not linked", error.message
    user = auth.context.internal_adapter.find_user_by_email("unverified-link@example.com")[:user]
    assert_empty auth.context.internal_adapter.find_accounts(user["id"]).reject { |account| account["providerId"] == "credential" }
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

  def test_link_social_redirect_flow_links_account_on_callback
    issued_code_verifier = nil
    callback_code_verifier = nil
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: lambda do |data|
            issued_code_verifier = data[:codeVerifier]
            "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}"
          end,
          validate_authorization_code: lambda do |data|
            callback_code_verifier = data[:codeVerifier]
            {accessToken: "linked-access", refreshToken: "linked-refresh"}
          end,
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-redirect-linked",
                email: "redirect-link@example.com",
                name: "Redirect Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "redirect-link@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    response = auth.api.link_social(
      headers: {"cookie" => cookie},
      body: {provider: "github", callbackURL: "/linked", disableRedirect: true}
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/linked", headers.fetch("location")
    refute_includes headers.fetch("set-cookie", ""), "better-auth.session_token="
    account = auth.context.internal_adapter.find_accounts(user_id).find { |entry| entry["providerId"] == "github" }
    assert_equal "gh-redirect-linked", account["accountId"]
    assert_equal "linked-refresh", account["refreshToken"]
    assert_match(/\A[0-9a-f]{32}\z/, issued_code_verifier)
    assert_equal issued_code_verifier, callback_code_verifier
  end

  def test_link_social_redirect_flow_rejects_account_owned_by_another_user
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          create_authorization_url: ->(data) { "https://github.example/oauth?state=#{URI.encode_www_form_component(data[:state])}" },
          validate_authorization_code: ->(_data) { {accessToken: "linked-access"} },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-owned",
                email: "owner-one@example.com",
                name: "Owned",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {trusted_providers: ["github"], allow_different_emails: true}}
    )
    first_cookie = sign_up_cookie(auth, email: "owner-one@example.com")
    first_user_id = auth.api.get_session(headers: {"cookie" => first_cookie})[:user]["id"]
    auth.context.internal_adapter.create_account({
      "providerId" => "github",
      "accountId" => "gh-owned",
      "userId" => first_user_id
    })
    second_cookie = sign_up_cookie(auth, email: "owner-two@example.com")

    response = auth.api.link_social(
      headers: {"cookie" => second_cookie},
      body: {provider: "github", callbackURL: "/linked", disableRedirect: true}
    )
    state = URI.decode_www_form(URI.parse(response[:url]).query).assoc("state").last

    status, headers, _body = auth.api.callback_oauth(
      params: {providerId: "github"},
      query: {code: "code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_includes headers.fetch("location"), "error=account_already_linked_to_different_user"
  end

  def test_link_social_rejects_when_account_linking_is_disabled
    auth = build_auth(
      social_providers: {
        github: {
          id: "github",
          verify_id_token: ->(_token, _nonce = nil) { true },
          get_user_info: ->(_tokens) {
            {
              user: {
                id: "gh-disabled-link",
                email: "disabled-link@example.com",
                name: "Disabled Link",
                emailVerified: true
              }
            }
          }
        }
      },
      account: {account_linking: {enabled: false, trusted_providers: ["github"]}}
    )
    cookie = sign_up_cookie(auth, email: "disabled-link@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.link_social(
        headers: {"cookie" => cookie},
        body: {provider: "github", idToken: {token: "id-token"}}
      )
    end

    assert_equal "Account not linked - untrusted provider", error.message
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Social User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
