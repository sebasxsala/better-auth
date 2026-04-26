# frozen_string_literal: true

require "base64"
require "json"
require "rack/mock"
require_relative "../../test_helper"

class BetterAuthPluginsSSOSAMLTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_saml_metadata_authn_request_and_acs_flow
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {
          entryPoint: "https://idp.example.com/sso",
          cert: "test-cert",
          callbackUrl: "http://localhost:3000/saml/callback",
          audience: "better-auth-ruby",
          spMetadata: {entityId: "http://localhost:3000/api/auth/sso/saml2/sp/metadata"}
        }
      }
    )

    metadata = auth.api.sp_metadata(query: {providerId: "saml", format: "json"})
    assert_equal "saml", metadata.fetch(:providerId)
    assert_includes metadata.fetch(:metadata), "EntityDescriptor"

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})
    uri = URI.parse(sign_in[:url])
    params = Rack::Utils.parse_query(uri.query)
    assert_equal "https://idp.example.com/sso", "#{uri.scheme}://#{uri.host}#{uri.path}"
    assert params.fetch("SAMLRequest")
    assert params.fetch("RelayState")

    response = Base64.strict_encode64(JSON.generate({email: "saml@example.com", name: "SAML User", id: "saml-sub"}))
    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: response, RelayState: params.fetch("RelayState")},
      headers: {"origin" => "https://idp.example.com"},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/dashboard", headers.fetch("location")
    assert_includes headers.fetch("set-cookie"), "better-auth.session_token="
    assert auth.context.internal_adapter.find_user_by_email("saml@example.com")[:user]
  end

  def test_saml_rejects_malicious_relay_state_and_replayed_response
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.example.com",
        domain: "example.com",
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "https://evil.example.com"})
    relay_state = Rack::Utils.parse_query(URI.parse(sign_in[:url]).query).fetch("RelayState")
    response = Base64.strict_encode64(JSON.generate({email: "saml@example.com", name: "SAML User", id: "assertion-1"}))

    status, headers, _body = auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response, RelayState: relay_state}, as_response: true)
    assert_equal 302, status
    refute_includes headers.fetch("location"), "evil.example.com"

    replay = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response, RelayState: relay_state})
    end
    assert_equal 400, replay.status_code
    assert_equal "SAML response has already been used", replay.message
  end

  def test_saml_origin_check_is_skipped_only_for_saml_callbacks
    auth = build_auth
    app = auth.handler
    env = Rack::MockRequest.env_for(
      "http://localhost:3000/api/auth/sso/saml2/callback/saml",
      :method => "POST",
      "CONTENT_TYPE" => "application/json",
      "HTTP_ORIGIN" => "https://idp.example.com",
      :input => JSON.generate({SAMLResponse: Base64.strict_encode64(JSON.generate({email: "user@example.com"}))})
    )

    status, = app.call(env)
    refute_equal 403, status
  end

  private

  def build_auth
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.sso]
    )
  end

  def sign_up_cookie(auth)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: "owner@example.com", password: "password123", name: "Owner"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
