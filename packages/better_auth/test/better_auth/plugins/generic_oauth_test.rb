# frozen_string_literal: true

require "json"
require "rack/mock"
require "socket"
require_relative "../../test_helper"

class BetterAuthPluginsGenericOAuthTest < Minitest::Test
  SECRET = "phase-eight-secret-with-enough-entropy-123"

  def test_sign_in_oauth2_generates_authorization_url_with_state_and_scopes
    auth = build_auth

    result = auth.api.sign_in_with_oauth2(
      body: {
        providerId: "custom",
        callbackURL: "/dashboard",
        newUserCallbackURL: "/welcome",
        scopes: ["calendar"],
        disableRedirect: true
      }
    )
    uri = URI.parse(result[:url])
    params = Rack::Utils.parse_query(uri.query)

    assert_equal false, result[:redirect]
    assert_equal "https", uri.scheme
    assert_equal "provider.example.com", uri.host
    assert_equal "/authorize", uri.path
    assert_equal "client-id", params["client_id"]
    assert_equal "code", params["response_type"]
    assert_equal "calendar profile email", params["scope"]
    assert_equal "http://localhost:3000/api/auth/oauth2/callback/custom", params["redirect_uri"]
    assert params["state"]
  end

  def test_sign_in_oauth2_supports_dynamic_authorization_params_and_response_mode
    auth = build_auth(
      provider_overrides: {
        authorization_url_params: ->(ctx) { {audience: "api", origin: ctx.context.base_url} },
        response_mode: "query"
      }
    )

    result = auth.api.sign_in_with_oauth2(body: {providerId: "custom", disableRedirect: true})
    params = Rack::Utils.parse_query(URI.parse(result[:url]).query)

    assert_equal "api", params.fetch("audience")
    assert_equal "http://localhost:3000/api/auth", params.fetch("origin")
    assert_equal "query", params.fetch("response_mode")
  end

  def test_callback_creates_user_account_session_and_redirects_new_user
    auth = build_auth
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/welcome", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    user = auth.context.internal_adapter.find_user_by_email("oauth@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("oauth-sub", "custom")
    assert_equal user["id"], account["userId"]
    assert_equal "access-token", account["accessToken"]
    assert_equal "refresh-token", account["refreshToken"]
    assert_equal "openid,email", account["scope"]
  end

  def test_state_cookie_is_set_and_cleared_for_database_state_strategy
    auth = build_auth
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    data = JSON.parse(body.join)
    state = Rack::Utils.parse_query(URI.parse(data.fetch("url")).query).fetch("state")

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.state="

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_cookie_state_strategy_uses_oauth_state_cookie
    auth = build_auth(account: {store_state_strategy: "cookie"})
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard", newUserCallbackURL: "/welcome"},
      as_response: true
    )
    data = JSON.parse(body.join)
    state = Rack::Utils.parse_query(URI.parse(data.fetch("url")).query).fetch("state")

    assert_equal 200, status
    assert_includes headers.fetch("set-cookie"), "better-auth.oauth_state="

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/welcome", callback_headers.fetch("location")
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.oauth_state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_cookie_state_strategy_rejects_state_mismatch
    auth = build_auth(account: {store_state_strategy: "cookie"}, on_api_error: {error_url: "/error"})
    _status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: "#{state}-tampered"},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/error?error=state_mismatch", callback_headers.fetch("location")
    state_cookie = callback_headers.fetch("set-cookie").lines.find { |line| line.start_with?("better-auth.oauth_state=") }
    assert state_cookie
    assert_includes state_cookie, "Max-Age=0"
  end

  def test_cookie_state_strategy_rejects_missing_state_cookie
    auth = build_auth(account: {store_state_strategy: "cookie"}, on_api_error: {error_url: "/error"})
    _status, _headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", callbackURL: "/dashboard"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, callback_status
    assert_equal "/error?error=state_mismatch", callback_headers.fetch("location")
  end

  def test_callback_reuses_existing_user_and_honors_disable_implicit_sign_up
    disabled = build_auth(disable_implicit_sign_up: true)
    sign_in = disabled.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = disabled.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/error?error=signup_disabled", headers.fetch("location")

    requested = build_auth(disable_implicit_sign_up: true)
    sign_in = requested.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard", errorCallbackURL: "/error", requestSignUp: true})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = requested.api.o_auth2_callback(params: {providerId: "custom"}, query: {code: "oauth-code", state: state}, as_response: true)

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
  end

  def test_link_account_generates_link_state_and_callback_links_to_current_user
    auth = build_auth(user_info: {id: "linked-sub", email: "link@example.com", name: "Linked User"})
    cookie = sign_up_cookie(auth, email: "link@example.com")
    link = auth.api.o_auth2_link_account(
      headers: {"cookie" => cookie},
      body: {providerId: "custom", callbackURL: "/settings", scopes: ["files"]}
    )
    state = Rack::Utils.parse_query(URI.parse(link[:url]).query).fetch("state")

    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/settings", headers.fetch("location")
    user = auth.context.internal_adapter.find_user_by_email("link@example.com")[:user]
    account = auth.context.internal_adapter.find_account_by_provider_id("linked-sub", "custom")
    assert_equal user["id"], account["userId"]
  end

  def test_invalid_provider_and_issuer_mismatch_errors
    auth = build_auth

    provider_error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_with_oauth2(body: {providerId: "missing"})
    end
    assert_equal 400, provider_error.status_code
    assert_equal "No config found for provider missing", provider_error.message

    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", errorCallbackURL: "/error"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    status, headers, _body = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state, iss: "https://wrong.example.com"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/error?error=issuer_mismatch", headers.fetch("location")
  end

  def test_callback_redirects_when_custom_get_token_raises
    auth = build_auth(
      provider_overrides: {
        get_token: ->(**_data) { raise "provider down" }
      }
    )
    status, headers, body = auth.api.sign_in_with_oauth2(
      body: {providerId: "custom", errorCallbackURL: "/error"},
      as_response: true
    )
    state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

    callback_status, callback_headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      as_response: true
    )

    assert_equal 200, status
    assert_equal 302, callback_status
    assert_equal "/error?error=oauth_code_verification_failed", callback_headers.fetch("location")
  end

  def test_standard_http_token_exchange_supports_headers_basic_auth_params_and_userinfo_mapping
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          authorization_headers: {"X-Custom-Header" => "test-value"},
          token_url_params: ->(_ctx) { {audience: "api", resource: "calendar"} },
          authentication: "basic",
          pkce: true
        }
      )
      status, headers, body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(body.join).fetch("url")).query).fetch("state")

      callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
        as_response: true
      )

      assert_equal 200, status
      assert_equal 302, callback_status
      assert_equal "/dashboard", callback_headers.fetch("location")
      token_request = requests.find { |request| request[:path] == "/token" }
      assert token_request
      assert_equal "POST", token_request.fetch(:method)
      assert_equal "test-value", token_request.fetch(:headers).fetch("x-custom-header")
      assert_match(/\ABasic /, token_request.fetch(:headers).fetch("authorization"))
      assert_equal "oauth-code", token_request.fetch(:params).fetch("code")
      assert_equal "api", token_request.fetch(:params).fetch("audience")
      assert_equal "calendar", token_request.fetch(:params).fetch("resource")
      refute token_request.fetch(:params).key?("client_secret")

      userinfo_request = requests.find { |request| request[:path] == "/userinfo" }
      assert_equal "Bearer http-access-token", userinfo_request.fetch(:headers).fetch("authorization")
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      assert_equal "http-access-token", account.fetch("accessToken")
      assert_equal "http-refresh-token", account.fetch("refreshToken")
      assert_equal "openid,email", account.fetch("scope")
      assert_instance_of Time, account.fetch("accessTokenExpiresAt")
      assert_instance_of Time, account.fetch("refreshTokenExpiresAt")
    end
  end

  def test_provider_helper_factories_match_upstream_defaults
    assert_equal(
      {
        provider_id: "auth0",
        discovery_url: "https://tenant.auth0.com/.well-known/openid-configuration",
        scopes: ["openid", "profile", "email"]
      },
      BetterAuth::Plugins.auth0(client_id: "id", client_secret: "secret", domain: "https://tenant.auth0.com").slice(:provider_id, :discovery_url, :scopes)
    )
    assert_equal "https://okta.example.com/oauth2/default/.well-known/openid-configuration", BetterAuth::Plugins.okta(client_id: "id", client_secret: "secret", issuer: "https://okta.example.com/oauth2/default/")[:discovery_url]
    assert_equal "https://realm.example.com/realms/main/.well-known/openid-configuration", BetterAuth::Plugins.keycloak(client_id: "id", client_secret: "secret", issuer: "https://realm.example.com/realms/main/")[:discovery_url]
    assert_equal "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", BetterAuth::Plugins.microsoft_entra_id(client_id: "id", client_secret: "secret", tenant_id: "common")[:authorization_url]
    assert_equal "https://slack.com/openid/connect/authorize", BetterAuth::Plugins.slack(client_id: "id", client_secret: "secret")[:authorization_url]
    assert_equal "line-jp", BetterAuth::Plugins.line(provider_id: "line-jp", client_id: "id", client_secret: "secret")[:provider_id]
    assert_equal "https://gumroad.com/oauth/authorize", BetterAuth::Plugins.gumroad(client_id: "id", client_secret: "secret")[:authorization_url]
    assert_equal "post", BetterAuth::Plugins.hubspot(client_id: "id", client_secret: "secret")[:authentication]
    assert_equal "https://www.patreon.com/oauth2/authorize", BetterAuth::Plugins.patreon(client_id: "id", client_secret: "secret")[:authorization_url]
  end

  def test_generic_oauth_provider_is_available_to_account_info
    auth = build_auth(user_info: {id: "info-sub", email: "info@example.com", name: "Info User", emailVerified: true})
    sign_in = auth.api.sign_in_with_oauth2(body: {providerId: "custom", callbackURL: "/dashboard"})
    state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("state")
    _status, headers, = auth.api.o_auth2_callback(
      params: {providerId: "custom"},
      query: {code: "oauth-code", state: state},
      as_response: true
    )
    account = auth.context.internal_adapter.find_account_by_provider_id("info-sub", "custom")

    info = auth.api.account_info(
      headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))},
      query: {accountId: account.fetch("id")}
    )

    assert_equal "info-sub", info[:id] || info["id"]
    assert_equal "info@example.com", info[:email] || info["email"]
  end

  def test_generic_oauth_provider_refreshes_access_tokens_through_account_routes
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo",
          authentication: "basic"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      auth.context.internal_adapter.update_account(account.fetch("id"), "accessTokenExpiresAt" => Time.now - 60)

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "refreshed-access-token", token.fetch(:accessToken)
      refresh_request = requests.reverse.find { |request| request[:path] == "/token" }
      assert_equal "refresh_token", refresh_request.fetch(:params).fetch("grant_type")
      assert_equal "http-refresh-token", refresh_request.fetch(:params).fetch("refresh_token")
      assert_match(/\ABasic /, refresh_request.fetch(:headers).fetch("authorization"))
    end
  end

  def test_generic_oauth_sets_and_refreshes_account_cookie
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account_cookie = decoded_account_cookie(callback_headers.fetch("set-cookie"), auth)

      assert_equal "custom", account_cookie.fetch("providerId")
      assert_equal "http-sub", account_cookie.fetch("accountId")
      assert_equal "http-access-token", account_cookie.fetch("accessToken")

      _token_status, token_headers, = auth.api.refresh_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"},
        as_response: true
      )
      refreshed_cookie = decoded_account_cookie(token_headers.fetch("set-cookie"), auth)

      assert_equal "refreshed-access-token", refreshed_cookie.fetch("accessToken")
      assert_equal "http-refresh-token", refreshed_cookie.fetch("refreshToken")
    end
  end

  def test_account_routes_can_read_generic_oauth_account_cookie
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      auth.context.internal_adapter.delete_account(account.fetch("id"))

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "http-access-token", token.fetch(:accessToken)
      assert_equal ["openid", "email"], token.fetch(:scopes)
    end
  end

  def test_generic_oauth_encrypts_stored_tokens_and_returns_decrypted_access_token
    requests = []
    with_oauth_server(requests) do |base_url|
      auth = build_auth(
        account: {store_account_cookie: true, encrypt_oauth_tokens: true},
        provider_overrides: {
          get_token: nil,
          get_user_info: nil,
          authorization_url: "#{base_url}/authorize",
          token_url: "#{base_url}/token",
          user_info_url: "#{base_url}/userinfo"
        }
      )
      _status, sign_in_headers, sign_in_body = auth.api.sign_in_with_oauth2(
        body: {providerId: "custom", callbackURL: "/dashboard"},
        as_response: true
      )
      state = Rack::Utils.parse_query(URI.parse(JSON.parse(sign_in_body.join).fetch("url")).query).fetch("state")
      _callback_status, callback_headers, = auth.api.o_auth2_callback(
        params: {providerId: "custom"},
        query: {code: "oauth-code", state: state},
        headers: {"cookie" => cookie_header(sign_in_headers.fetch("set-cookie"))},
        as_response: true
      )
      account = auth.context.internal_adapter.find_account_by_provider_id("http-sub", "custom")
      account_cookie = decoded_account_cookie(callback_headers.fetch("set-cookie"), auth)

      refute_equal "http-access-token", account.fetch("accessToken")
      refute_equal "http-refresh-token", account.fetch("refreshToken")
      refute_equal "http-access-token", account_cookie.fetch("accessToken")

      token = auth.api.get_access_token(
        headers: {"cookie" => cookie_header(callback_headers.fetch("set-cookie"))},
        body: {providerId: "custom"}
      )

      assert_equal "http-access-token", token.fetch(:accessToken)

      auth.context.internal_adapter.update_account(account.fetch("id"), "accessTokenExpiresAt" => Time.now - 60)
      refreshed = auth.api.get_access_token(
        headers: {"cookie" => cookie_header_without_account_data(callback_headers.fetch("set-cookie"), auth)},
        body: {providerId: "custom"}
      )

      assert_equal "refreshed-access-token", refreshed.fetch(:accessToken)
    end
  end

  private

  def build_auth(options = {})
    user_info = options.delete(:user_info) || {id: "oauth-sub", email: "oauth@example.com", name: "OAuth User", emailVerified: true, image: "https://example.com/avatar.png"}
    disable_implicit = options.delete(:disable_implicit_sign_up)
    provider_overrides = options.delete(:provider_overrides) || {}
    extra_options = options

    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: :memory,
        plugins: [
          BetterAuth::Plugins.generic_oauth(
            config: [
              {
                provider_id: "custom",
                authorization_url: "https://provider.example.com/authorize",
                token_url: "https://provider.example.com/token",
                issuer: "https://provider.example.com",
                client_id: "client-id",
                client_secret: "client-secret",
                scopes: ["profile", "email"],
                disable_implicit_sign_up: disable_implicit,
                get_token: ->(code:, **_data) {
                  raise "unexpected code" unless code == "oauth-code"

                  {
                    accessToken: "access-token",
                    refreshToken: "refresh-token",
                    idToken: "id-token",
                    scopes: ["openid", "email"]
                  }
                },
                get_user_info: ->(_tokens) { user_info }
              }.merge(provider_overrides)
            ]
          )
        ]
      }.merge(extra_options)
    )
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  def cookie_header_without_account_data(set_cookie, auth)
    account_cookie = auth.context.auth_cookies[:account_data].name
    set_cookie.to_s.lines
      .reject { |line| line.start_with?("#{account_cookie}=") }
      .map { |line| line.split(";").first }
      .join("; ")
  end

  def decoded_account_cookie(set_cookie, auth)
    cookie_name = auth.context.auth_cookies[:account_data].name
    line = set_cookie.to_s.lines.find { |entry| entry.start_with?("#{cookie_name}=") && !entry.match?(/Max-Age=0/i) }
    value = line.to_s.split(";", 2).first.split("=", 2).last
    assert value && !value.empty?

    BetterAuth::Crypto.symmetric_decode_jwt(value, SECRET, "better-auth-account")
  end

  def with_oauth_server(requests)
    server = TCPServer.new("127.0.0.1", 0)
    thread = Thread.new do
      loop do
        socket = server.accept
        request_line = socket.gets.to_s
        method, target = request_line.split
        headers = {}
        while (line = socket.gets)
          line = line.chomp
          break if line.empty?

          key, value = line.split(":", 2)
          headers[key.downcase] = value.to_s.strip
        end
        body = socket.read(headers["content-length"].to_i).to_s
        uri = URI.parse(target)
        params = (method == "POST") ? Rack::Utils.parse_nested_query(body) : Rack::Utils.parse_nested_query(uri.query.to_s)
        requests << {method: method, path: uri.path, headers: headers, params: params}
        response_body = oauth_server_response_body(uri.path, params)
        socket.write "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: #{response_body.bytesize}\r\nconnection: close\r\n\r\n#{response_body}"
      rescue IOError
        break
      ensure
        socket&.close
      end
    end
    yield "http://127.0.0.1:#{server.addr[1]}"
  ensure
    server&.close
    thread&.join
  end

  def oauth_server_response_body(path, params = {})
    if path == "/token"
      access_token = (params["grant_type"] == "refresh_token") ? "refreshed-access-token" : "http-access-token"
      return JSON.generate(
        access_token: access_token,
        refresh_token: "http-refresh-token",
        expires_in: 3600,
        refresh_token_expires_in: 7200,
        scope: "openid email",
        token_type: "Bearer",
        raw_provider_field: "preserved"
      )
    end

    JSON.generate(
      sub: "http-sub",
      email: "http@example.com",
      name: "HTTP User",
      email_verified: true,
      picture: "https://example.com/http.png"
    )
  end
end
