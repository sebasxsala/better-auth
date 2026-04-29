# frozen_string_literal: true

require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsOAuthProviderTest < Minitest::Test
  SECRET = "phase-eleven-secret-with-enough-entropy-123"

  def test_validate_issuer_url_matches_rfc_9207_upstream_behavior
    assert_equal "https://issuer.example.com", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("https://issuer.example.com/")
    assert_equal "https://issuer.example.com/auth", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://issuer.example.com/auth?x=1#frag")
    assert_equal "http://localhost:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://localhost:3000/")
    assert_equal "http://127.0.0.1:3000", BetterAuth::Plugins::OAuthProvider.validate_issuer_url("http://127.0.0.1:3000/")
  end

  def test_schema_is_self_contained_and_does_not_register_core_oidc_application_table
    auth = build_auth
    schema = BetterAuth::Schema.auth_tables(auth.options)

    assert schema.key?("oauthClient")
    assert schema.key?("oauthAccessToken")
    assert schema.key?("oauthRefreshToken")
    assert schema.key?("oauthConsent")
    refute schema.key?("oauthApplication")
  end

  def test_metadata_client_management_introspection_and_revocation
    auth = build_auth
    cookie = sign_up_cookie(auth)

    metadata = auth.api.get_o_auth_server_config
    assert_equal "http://localhost:3000", metadata[:issuer]
    assert_equal "http://localhost:3000/api/auth/oauth2/introspect", metadata[:introspection_endpoint]
    assert_equal "http://localhost:3000/api/auth/oauth2/revoke", metadata[:revocation_endpoint]
    assert_includes metadata[:grant_types_supported], "client_credentials"

    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Machine Client",
        scope: "read write"
      }
    )
    assert client[:client_id]
    assert client[:client_secret]

    public_client = auth.api.get_o_auth_client_public(query: {client_id: client[:client_id]})
    assert_equal "Machine Client", public_client[:client_name]
    assert_nil public_client[:client_secret]

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "client_credentials",
        client_id: client[:client_id],
        client_secret: client[:client_secret],
        scope: "read"
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert tokens[:access_token]
    assert_equal "read", tokens[:scope]

    active = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal true, active[:active]
    assert_equal client[:client_id], active[:client_id]
    assert_equal "read", active[:scope]

    revoke = auth.api.o_auth2_revoke(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal({revoked: true}, revoke)

    inactive = auth.api.o_auth2_introspect(
      body: {
        token: tokens[:access_token],
        token_type_hint: "access_token",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal false, inactive[:active]
  end

  def test_client_management_requires_owner_session_for_get_and_delete
    auth = build_auth
    owner_cookie = sign_up_cookie(auth, email: "oauth-owner@example.com")
    other_cookie = sign_up_cookie(auth, email: "oauth-other@example.com")
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => owner_cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["client_credentials"],
        response_types: [],
        client_name: "Owned Client",
        scope: "read"
      }
    )

    get_error = assert_raises(BetterAuth::APIError) do
      auth.api.get_o_auth_client(headers: {"cookie" => other_cookie}, params: {id: client[:client_id]})
    end
    assert_equal 404, get_error.status_code

    delete_error = assert_raises(BetterAuth::APIError) do
      auth.api.delete_o_auth_client(headers: {"cookie" => other_cookie}, body: {client_id: client[:client_id]})
    end
    assert_equal 404, delete_error.status_code

    assert_equal "Owned Client", auth.api.get_o_auth_client(headers: {"cookie" => owner_cookie}, params: {id: client[:client_id]})[:client_name]
    assert_equal({status: true}, auth.api.delete_o_auth_client(headers: {"cookie" => owner_cookie}, body: {client_id: client[:client_id]}))
  end

  def test_authorization_code_flow_requires_and_records_consent
    auth = build_auth(consent_page: "/consent")
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        client_name: "Browser Client",
        scope: "read write"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-123",
        prompt: "consent"
      },
      as_response: true
    )
    assert_equal 302, status
    consent_redirect = URI.parse(headers.fetch("location"))
    assert_equal "/consent", consent_redirect.path
    consent_code = Rack::Utils.parse_query(consent_redirect.query).fetch("consent_code")

    consent = auth.api.o_auth2_consent(
      headers: {"cookie" => cookie},
      body: {accept: true, consent_code: consent_code}
    )
    callback = URI.parse(consent.fetch(:redirectURI))
    params = Rack::Utils.parse_query(callback.query)
    assert_equal "state-123", params.fetch("state")
    assert_equal "http://localhost:3000", params.fetch("iss")
    assert params.fetch("code")

    tokens = auth.api.o_auth2_token(
      body: {
        grant_type: "authorization_code",
        code: params.fetch("code"),
        redirect_uri: "https://resource.example/callback",
        client_id: client[:client_id],
        client_secret: client[:client_secret]
      }
    )
    assert_equal "Bearer", tokens[:token_type]
    assert_equal "read", tokens[:scope]
    assert tokens[:refresh_token]

    consent_record = auth.context.adapter.find_one(model: "oauthConsent", where: [{field: "clientId", value: client[:client_id]}])
    assert_equal true, consent_record.fetch("consentGiven")
  end

  def test_authorize_prompt_none_returns_consent_required_without_prior_consent
    auth = build_auth
    cookie = sign_up_cookie(auth)
    client = auth.api.register_o_auth_client(
      headers: {"cookie" => cookie},
      body: {
        redirect_uris: ["https://resource.example/callback"],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"],
        client_name: "Prompt None Client",
        scope: "read"
      }
    )

    status, headers, = auth.api.o_auth2_authorize(
      headers: {"cookie" => cookie},
      query: {
        response_type: "code",
        client_id: client[:client_id],
        redirect_uri: "https://resource.example/callback",
        scope: "read",
        state: "state-456",
        prompt: "none"
      },
      as_response: true
    )

    assert_equal 302, status
    params = Rack::Utils.parse_query(URI.parse(headers.fetch("location")).query)
    assert_equal "consent_required", params.fetch("error")
    assert_equal "state-456", params.fetch("state")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      email_and_password: {enabled: true},
      plugins: [BetterAuth::Plugins.oauth_provider({scopes: ["read", "write"]}.merge(options))]
    )
  end

  def sign_up_cookie(auth, email: "oauth-provider@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "OAuth Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
