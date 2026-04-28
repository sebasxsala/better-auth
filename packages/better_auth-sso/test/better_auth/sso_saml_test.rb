# frozen_string_literal: true

require "base64"
require "json"
require "rack/mock"
require_relative "../test_helper"

class BetterAuthPluginsSSOSAMLTest < Minitest::Test
  SECRET = "phase-twelve-secret-with-enough-entropy-123"

  def test_sso_saml_hooks_merge_default_parser_options
    base = {organization_provisioning: {role: "admin"}, saml: {validate_response: ->(**) { true }}}
    parser_options = {saml: {parse_response: ->(**) { {email: "ada@example.com"} }}}

    merged = BetterAuth::SSO::SAMLHooks.merge_options(base, parser_options)

    assert_equal "admin", merged.dig(:organization_provisioning, :role)
    assert merged.dig(:saml, :validate_response)
    assert merged.dig(:saml, :parse_response)
  end

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

  def test_saml_response_validator_can_reject_assertions
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            validate_response: ->(response:, provider:, context:) do
              calls << [provider.fetch("providerId"), context.context.base_url]
              response[:email] == "allowed@example.com"
            end
          }
        )
      ]
    )
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
    response = Base64.strict_encode64(JSON.generate({email: "blocked@example.com", name: "Blocked", id: "blocked-1"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.acs_endpoint(params: {providerId: "saml"}, body: {SAMLResponse: response})
    end
    assert_equal 400, error.status_code
    assert_equal "Invalid SAML response", error.message
    assert_equal [["saml", "http://localhost:3000/api/auth"]], calls
  end

  def test_saml_response_parser_hook_enables_optional_real_xml_validator_adapter
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            parse_response: ->(raw_response:, provider:, context:) do
              calls << [raw_response, provider.fetch("providerId"), context.context.base_url]
              {email: "parsed@example.com", name: "Parsed User", id: "parsed-assertion"}
            end
          }
        )
      ]
    )
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

    raw_response = "signed-xml-from-sso-package"
    status, headers, _body = auth.api.acs_endpoint(
      params: {providerId: "saml"},
      body: {SAMLResponse: raw_response},
      as_response: true
    )

    assert_equal 302, status
    assert_equal "/", headers.fetch("location")
    assert auth.context.internal_adapter.find_user_by_email("parsed@example.com")[:user]
    assert_equal [[raw_response, "saml", "http://localhost:3000/api/auth"]], calls
  end

  def test_saml_auth_request_url_hook_enables_optional_real_xml_request_adapter
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.sso(
          saml: {
            auth_request_url: ->(provider:, relay_state:, context:) do
              calls << [provider.fetch("providerId"), relay_state, context.context.base_url]
              "https://idp.example.com/real-saml?RelayState=#{URI.encode_www_form_component(relay_state)}"
            end
          }
        )
      ]
    )
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

    sign_in = auth.api.sign_in_sso(body: {providerId: "saml", callbackURL: "/dashboard"})

    assert_match %r{\Ahttps://idp.example.com/real-saml\?RelayState=}, sign_in.fetch(:url)
    assert_equal "saml", calls.first.fetch(0)
    assert_equal "http://localhost:3000/api/auth", calls.first.fetch(2)
    assert calls.first.fetch(1).length.positive?
  end

  def test_saml_xml_response_rejects_missing_and_multiple_assertions
    no_assertion = Base64.strict_encode64("<Response></Response>")
    error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(no_assertion) }
    assert_equal 400, error.status_code
    assert_equal "SAML response contains no assertions", error.message

    multiple = Base64.strict_encode64("<Response><Assertion ID=\"one\"/><EncryptedAssertion ID=\"two\"/></Response>")
    multiple_error = assert_raises(BetterAuth::APIError) { BetterAuth::Plugins.sso_validate_single_saml_assertion!(multiple) }
    assert_equal 400, multiple_error.status_code
    assert_match(/expected exactly 1/, multiple_error.message)

    valid = Base64.strict_encode64("<Response><Assertion ID=\"one\"><Subject /></Assertion></Response>")
    assert_equal true, BetterAuth::Plugins.sso_validate_single_saml_assertion!(valid)
  end

  def test_saml_algorithm_validation_matches_upstream_policy
    valid = saml_algorithm_xml(
      signature_algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      digest_algorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
      key_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      data_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    )

    assert_equal true, BetterAuth::Plugins.sso_validate_saml_algorithms!(valid)

    error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(
        saml_algorithm_xml(signature_algorithm: "http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
        on_deprecated: "reject"
      )
    end
    assert_equal 400, error.status_code
    assert_match(/deprecated signature algorithm/, error.message)

    unknown_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(saml_algorithm_xml(digest_algorithm: "urn:example:sha257"))
    end
    assert_equal 400, unknown_error.status_code
    assert_match(/not recognized/, unknown_error.message)

    allow_list_error = assert_raises(BetterAuth::APIError) do
      BetterAuth::Plugins.sso_validate_saml_algorithms!(
        saml_algorithm_xml(data_encryption_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm"),
        allowed_data_encryption_algorithms: ["http://www.w3.org/2009/xmlenc11#aes128-gcm"]
      )
    end
    assert_match(/not in allow-list/, allow_list_error.message)
    assert_equal true, BetterAuth::Plugins.sso_validate_saml_algorithms!("<Response />")
  end

  def test_sso_assigns_new_domain_user_to_verified_provider_organization
    auth = build_auth(plugins: [BetterAuth::Plugins.organization, BetterAuth::Plugins.sso])
    owner_cookie = sign_up_cookie(auth, email: "owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Example Org", slug: "example"})
    auth.api.register_sso_provider(
      headers: {"cookie" => owner_cookie},
      body: {
        providerId: "saml-org",
        issuer: "https://idp.example.com",
        domain: "example.com",
        organizationId: organization.fetch("id"),
        domainVerified: true,
        samlConfig: {entryPoint: "https://idp.example.com/sso", cert: "test-cert", audience: "better-auth-ruby"}
      }
    )
    response = Base64.strict_encode64(JSON.generate({email: "new-user@example.com", name: "New User", id: "assertion-org-1"}))

    auth.api.acs_endpoint(params: {providerId: "saml-org"}, body: {SAMLResponse: response}, as_response: true)

    user = auth.context.internal_adapter.find_user_by_email("new-user@example.com").fetch(:user)
    member = auth.context.adapter.find_one(
      model: "member",
      where: [
        {field: "organizationId", value: organization.fetch("id")},
        {field: "userId", value: user.fetch("id")}
      ]
    )
    assert_equal "member", member.fetch("role")
  end

  private

  def build_auth(options = {})
    BetterAuth.auth(
      {
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: :memory,
        plugins: [BetterAuth::Plugins.sso]
      }.merge(options)
    )
  end

  def sign_up_cookie(auth, email: "owner@example.com")
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end

  def saml_algorithm_xml(signature_algorithm: nil, digest_algorithm: nil, key_encryption_algorithm: nil, data_encryption_algorithm: nil)
    signature = signature_algorithm ? "<ds:SignatureMethod Algorithm=\"#{signature_algorithm}\"/>" : nil
    digest = digest_algorithm ? "<ds:DigestMethod Algorithm=\"#{digest_algorithm}\"/>" : nil
    key_encryption = key_encryption_algorithm ? "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"#{key_encryption_algorithm}\"/></xenc:EncryptedKey>" : nil
    data_encryption = data_encryption_algorithm ? "<xenc:EncryptedData><xenc:EncryptionMethod Algorithm=\"#{data_encryption_algorithm}\"/></xenc:EncryptedData>" : nil

    <<~XML
      <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
        #{signature}
        #{digest}
        <xenc:EncryptedAssertion>
          #{key_encryption}
          #{data_encryption}
        </xenc:EncryptedAssertion>
      </samlp:Response>
    XML
  end
end
