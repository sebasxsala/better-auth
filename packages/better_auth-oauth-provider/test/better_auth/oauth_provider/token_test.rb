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

  def test_client_credentials_rejects_oidc_user_scopes
    auth = build_auth(scopes: ["openid", "profile", "email", "offline_access", "read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "openid profile email offline_access read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "openid read"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/invalid_scope/, error.message)
  end

  def test_client_credentials_uses_configured_default_scopes_when_client_has_none
    auth = build_auth(scopes: ["read", "write"], client_credential_grant_default_scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read write")
    auth.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}], update: {scopes: nil})

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )

    assert_equal "read", tokens[:scope]
  end

  def test_client_credentials_preserves_explicit_empty_client_scopes
    auth = build_auth(scopes: ["read", "write"], client_credential_grant_default_scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read write")
    auth.context.adapter.update(model: "oauthClient", where: [{field: "clientId", value: client[:client_id]}], update: {scopes: []})

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )

    assert_equal "", tokens[:scope]
  end

  def test_resource_defaults_to_base_url_audience_allow_list
    auth = build_auth(scopes: ["read"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.o_auth2_token(
        body: {
          grant_type: "client_credentials",
          client_id: client[:client_id],
          client_secret: client[:client_secret],
          scope: "read",
          resource: "https://evil.example"
        }
      )
    end

    assert_equal 400, error.status_code
    assert_match(/requested resource invalid/, error.message)
  end

  def test_openid_resource_allows_userinfo_audience
    auth = build_auth(scopes: ["openid"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    tokens = issue_authorization_code_tokens(
      auth,
      cookie,
      client,
      scope: "openid",
      resource: "http://localhost:3000/api/auth/oauth2/userinfo"
    )

    assert_equal "http://localhost:3000/api/auth/oauth2/userinfo", tokens[:audience]
  end

  def test_jwt_plugin_signs_jwt_access_tokens_and_introspection_verifies_them
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.jwt(jwks: {key_pair_config: {alg: "EdDSA"}}),
        BetterAuth::Plugins.oauth_provider(scopes: ["read"], allow_dynamic_client_registration: true)
      ]
    )
    cookie = sign_up_cookie(auth, email: "jwt-access@example.com")
    client = create_client(auth, cookie, grant_types: ["client_credentials"], response_types: [], scope: "read")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read",
        resource: "http://localhost:3000"
      }
    )
    _payload, header = JWT.decode(tokens[:access_token], nil, false)
    active = auth.api.o_auth2_introspect(body: introspect_body(client, tokens[:access_token], hint: "access_token"))

    assert_equal "EdDSA", header["alg"]
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]
  end

  def test_id_token_expiration_is_configurable_in_hs256_fallback
    auth = build_auth(scopes: ["openid"], disable_jwt_plugin: true, id_token_expires_in: 1234)
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, scope: "openid", skip_consent: true)

    tokens = issue_authorization_code_tokens(auth, cookie, client, scope: "openid")
    payload = decode_id_token(tokens[:id_token], client)

    assert_equal 1234, payload.fetch("exp") - payload.fetch("iat")
  end
end
