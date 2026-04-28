# frozen_string_literal: true

require "json"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsSSOTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_registers_sso_schema_and_provider_crud_routes
    auth = build_auth
    cookie = sign_up_cookie(auth)

    provider = auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "acme",
        issuer: "https://idp.acme.test",
        domain: "acme.test",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          authorizationEndpoint: "https://idp.acme.test/authorize",
          tokenEndpoint: "https://idp.acme.test/token",
          userInfoEndpoint: "https://idp.acme.test/userinfo"
        }
      }
    )

    assert_equal "acme", provider.fetch("providerId")
    assert_equal "https://idp.acme.test", provider.fetch("issuer")
    assert_equal "acme.test", provider.fetch("domain")
    refute provider.key?("clientSecret")

    listed = auth.api.list_sso_providers(headers: {"cookie" => cookie})
    assert_equal ["acme"], listed.fetch(:providers).map { |item| item.fetch("providerId") }

    fetched = auth.api.get_sso_provider(headers: {"cookie" => cookie}, params: {providerId: "acme"})
    assert_equal "acme", fetched.fetch("providerId")
    assert_includes fetched.fetch("spMetadataUrl"), "/sso/saml2/sp/metadata?providerId=acme"

    updated = auth.api.update_sso_provider(
      headers: {"cookie" => cookie},
      params: {providerId: "acme"},
      body: {domain: "new.acme.test"}
    )
    assert_equal "new.acme.test", updated.fetch("domain")
    assert_equal false, updated.fetch("domainVerified")

    deleted = auth.api.delete_sso_provider(headers: {"cookie" => cookie}, params: {providerId: "acme"})
    assert_equal({success: true}, deleted)
    assert_empty auth.api.list_sso_providers(headers: {"cookie" => cookie}).fetch(:providers)
  end

  def test_sign_in_sso_selects_provider_by_email_domain_and_redirects
    auth = build_auth
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "acme",
        issuer: "https://idp.acme.test",
        domain: "acme.test",
        oidcConfig: {
          clientId: "client-id",
          clientSecret: "client-secret",
          authorizationEndpoint: "https://idp.acme.test/authorize",
          tokenEndpoint: "https://idp.acme.test/token",
          userInfoEndpoint: "https://idp.acme.test/userinfo"
        }
      }
    )

    result = auth.api.sign_in_sso(body: {email: "someone@acme.test", callbackURL: "/dashboard"})
    uri = URI.parse(result[:url])
    params = Rack::Utils.parse_query(uri.query)

    assert_equal "https://idp.acme.test", "#{uri.scheme}://#{uri.host}"
    assert_equal "/authorize", uri.path
    assert_equal "client-id", params.fetch("client_id")
    assert_equal "http://localhost:3000/api/auth/sso/callback/acme", params.fetch("redirect_uri")
    assert params.fetch("state")
  end

  def test_domain_verification_lifecycle
    verification_requests = []
    auth = build_auth(
      domain_verification: {
        enabled: true,
        request: ->(provider:, token:, **_data) { verification_requests << [provider.fetch("providerId"), token] },
        verify: ->(domain:, token:, **_data) { domain == "acme.test" && token.start_with?("_better-auth-sso-verification-acme") }
      }
    )
    cookie = sign_up_cookie(auth)
    auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "acme",
        issuer: "https://idp.acme.test",
        domain: "acme.test",
        oidcConfig: {clientId: "client-id", clientSecret: "client-secret", authorizationEndpoint: "https://idp.acme.test/authorize"}
      }
    )

    requested = auth.api.request_domain_verification(headers: {"cookie" => cookie}, body: {providerId: "acme"})
    assert_equal true, requested.fetch(:success)
    assert_equal "acme", verification_requests.first.first
    assert_match(/\A_better-auth-sso-verification-acme-/, requested.fetch(:token))

    verified = auth.api.verify_domain(headers: {"cookie" => cookie}, body: {providerId: "acme"})
    assert_equal({success: true}, verified)
    provider = auth.api.get_sso_provider(headers: {"cookie" => cookie}, params: {providerId: "acme"})
    assert_equal true, provider.fetch("domainVerified")
  end

  def test_provider_access_is_limited_to_owner_or_org_admin
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.sso])
    owner_cookie = sign_up_cookie(auth, "owner@example.com")
    other_cookie = sign_up_cookie(auth, "other@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "SSO Org", slug: "sso-org"})

    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "owned",
        issuer: "https://idp.owned.test",
        domain: "owned.test",
        oidcConfig: {clientId: "owned-client", authorizationEndpoint: "https://idp.owned.test/authorize"}
      }
    )
    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "org",
        issuer: "https://idp.org.test",
        domain: "org.test",
        organizationId: organization.fetch("id"),
        oidcConfig: {clientId: "org-client", authorizationEndpoint: "https://idp.org.test/authorize"}
      }
    )

    owner_list = auth.api.list_sso_providers(headers: {"cookie" => owner_cookie}).fetch(:providers).map { |provider| provider.fetch("providerId") }
    assert_equal ["org", "owned"], owner_list.sort
    assert_empty auth.api.list_sso_providers(headers: {"cookie" => other_cookie}).fetch(:providers)

    error = assert_raises(BetterAuth::APIError) do
      auth.api.get_sso_provider(headers: {"cookie" => other_cookie}, params: {providerId: "owned"})
    end
    assert_equal 403, error.status_code
  end

  def test_provider_sanitization_masks_oidc_client_and_hides_saml_certificate
    auth = build_auth
    cookie = sign_up_cookie(auth)

    oidc = auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "oidc",
        issuer: "https://idp.oidc.test",
        domain: "oidc.test",
        oidcConfig: {
          clientId: "client-id-1234",
          clientSecret: "client-secret",
          authorizationEndpoint: "https://idp.oidc.test/authorize",
          tokenEndpoint: "https://idp.oidc.test/token"
        }
      }
    )
    assert_equal "oidc", oidc.fetch("type")
    assert_equal "****1234", oidc.fetch("oidcConfig").fetch("clientIdLastFour")
    refute oidc.fetch("oidcConfig").key?("clientId")
    refute oidc.fetch("oidcConfig").key?("clientSecret")

    saml = auth.api.register_sso_provider(
      headers: {"cookie" => cookie},
      body: {
        providerId: "saml",
        issuer: "https://idp.saml.test",
        domain: "saml.test",
        samlConfig: {entryPoint: "https://idp.saml.test/sso", cert: "not-a-cert", audience: "better-auth-ruby"}
      }
    )
    assert_equal "saml", saml.fetch("type")
    refute saml.fetch("samlConfig").key?("cert")
    assert_equal "Failed to parse certificate", saml.fetch("samlConfig").fetch("certificate").fetch(:error)
  end

  private

  def build_auth(plugin_options = nil, plugins: nil, **kwargs)
    plugin_options = (plugin_options || {}).merge(kwargs)
    BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: :memory,
      plugins: plugins || [BetterAuth::Plugins.sso(plugin_options)]
    )
  end

  def sign_up_cookie(auth, email = "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
