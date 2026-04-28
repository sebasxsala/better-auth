# frozen_string_literal: true

require "base64"
require "onelogin/ruby-saml"
require "uri"

module BetterAuth
  module SSO
    module SAML
      module_function

      DEFAULT_ATTRIBUTE_MAP = {
        email: %w[email mail emailAddress Email EmailAddress],
        name: %w[name displayName cn Name DisplayName],
        given_name: %w[givenName firstName FirstName],
        family_name: %w[familyName lastName LastName]
      }.freeze

      def sso_options(**options)
        {
          saml: {
            auth_request_url: auth_request_url(**options),
            parse_response: response_parser(**options)
          }
        }
      end

      def auth_request_url(settings: nil, request_options: {}, **_options)
        lambda do |provider:, relay_state:, context:|
          config = BetterAuth::Plugins.normalize_hash(provider["samlConfig"] || provider[:samlConfig] || {})
          saml_settings = settings.respond_to?(:call) ? settings.call(provider: provider, context: context, saml_config: config) : build_settings(provider, context, config, settings)
          OneLogin::RubySaml::Authrequest.new.create(saml_settings, {RelayState: relay_state}.merge(request_options))
        end
      end

      def response_parser(settings: nil, response_options: {}, attribute_map: DEFAULT_ATTRIBUTE_MAP, **_options)
        lambda do |raw_response:, provider:, context:|
          config = BetterAuth::Plugins.normalize_hash(provider["samlConfig"] || provider[:samlConfig] || {})
          saml_settings = settings.respond_to?(:call) ? settings.call(provider: provider, context: context, saml_config: config) : build_settings(provider, context, config, settings)
          validate_response_xml!(raw_response, config)
          response = OneLogin::RubySaml::Response.new(raw_response, {settings: saml_settings}.merge(response_options))
          unless response.is_valid?
            raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response")
          end

          attributes = response.attributes
          email = first_attribute(attributes, attribute_map.fetch(:email)) || response.nameid
          raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response") if email.to_s.empty?

          given_name = first_attribute(attributes, attribute_map.fetch(:given_name))
          family_name = first_attribute(attributes, attribute_map.fetch(:family_name))
          name = first_attribute(attributes, attribute_map.fetch(:name)) || [given_name, family_name].compact.join(" ").strip
          {
            email: email.to_s.downcase,
            name: name.to_s.empty? ? email.to_s : name.to_s,
            id: assertion_identifier(response, email),
            email_verified: true
          }
        end
      end

      def build_settings(provider, context, config, overrides = nil)
        settings = overrides || OneLogin::RubySaml::Settings.new
        provider_id = provider.fetch("providerId")
        base_url = context.context.base_url
        settings.assertion_consumer_service_url = config[:callback_url] || "#{base_url}/sso/saml2/sp/acs/#{provider_id}"
        settings.sp_entity_id = config.dig(:sp_metadata, :entity_id) || config[:audience] || "#{base_url}/sso/saml2/sp/metadata?providerId=#{URI.encode_www_form_component(provider_id)}"
        settings.idp_entity_id = provider["issuer"] || provider[:issuer]
        settings.idp_sso_service_url = config[:entry_point]
        settings.idp_cert = config[:cert] unless config[:cert].to_s.empty?
        settings.name_identifier_format = config[:identifier_format] unless config[:identifier_format].to_s.empty?
        settings.private_key = config[:sp_private_key] unless config[:sp_private_key].to_s.empty?
        settings.certificate = config[:sp_certificate] unless config[:sp_certificate].to_s.empty?
        settings.security[:want_assertions_signed] = config.fetch(:want_assertions_signed, true)
        settings.security[:want_messages_signed] = config.fetch(:want_messages_signed, false)
        settings.security[:want_assertions_encrypted] = config.fetch(:want_assertions_encrypted, false)
        settings.security[:strict_audience_validation] = true
        settings.security[:digest_method] = config[:digest_algorithm] || XMLSecurity::Document::SHA256
        settings.security[:signature_method] = config[:signature_algorithm] || XMLSecurity::Document::RSA_SHA256
        settings
      end

      def validate_response_xml!(raw_response, config)
        BetterAuth::Plugins.sso_validate_single_saml_assertion!(raw_response)
        xml = Base64.decode64(raw_response.to_s)
        BetterAuth::Plugins.sso_validate_saml_algorithms!(
          xml,
          on_deprecated: config.fetch(:on_deprecated_algorithm, "reject"),
          allowed_signature_algorithms: config[:allowed_signature_algorithms],
          allowed_digest_algorithms: config[:allowed_digest_algorithms],
          allowed_key_encryption_algorithms: config[:allowed_key_encryption_algorithms],
          allowed_data_encryption_algorithms: config[:allowed_data_encryption_algorithms]
        )
      rescue BetterAuth::APIError
        raise
      rescue
        raise BetterAuth::APIError.new("BAD_REQUEST", message: "Invalid SAML response")
      end

      def first_attribute(attributes, names)
        Array(names).each do |name|
          value = attributes[name]
          value = value.first if value.is_a?(Array)
          return value unless value.to_s.empty?
        end
        nil
      end

      def assertion_identifier(response, email)
        response.assertion_id || response.nameid || response.sessionindex || email
      end
    end
  end
end
