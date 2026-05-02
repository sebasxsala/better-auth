# frozen_string_literal: true

module BetterAuth
  module SSO
    module Linking
      module Types
        REQUIRED_PROFILE_KEYS = {
          provider_type: "providerType",
          provider_id: "providerId",
          account_id: "accountId",
          email: "email",
          email_verified: "emailVerified"
        }.freeze

        module_function

        def normalized_profile(profile)
          raw_attributes = raw_value(profile, :raw_attributes, "rawAttributes", "raw_attributes")
          source = BetterAuth::Plugins.normalize_hash(profile || {})
          normalized = {
            provider_type: source[:provider_type].to_s,
            provider_id: source[:provider_id].to_s,
            account_id: source[:account_id].to_s,
            email: source[:email].to_s.downcase,
            email_verified: !!source[:email_verified]
          }
          normalized[:name] = source[:name] if source.key?(:name)
          normalized[:image] = source[:image] if source.key?(:image)
          normalized[:raw_attributes] = raw_attributes unless raw_attributes.nil?

          missing = REQUIRED_PROFILE_KEYS.filter_map do |key, upstream_name|
            value = normalized[key]
            upstream_name if value.nil? || (value.respond_to?(:empty?) && value.empty?)
          end
          raise ArgumentError, "Missing normalized SSO profile fields: #{missing.join(", ")}" unless missing.empty?
          raise ArgumentError, "Invalid normalized SSO profile providerType: #{normalized[:provider_type]}" unless BetterAuth::SSO::Types.provider_type?(normalized[:provider_type])

          normalized.freeze
        end

        def raw_value(profile, *keys)
          return nil unless profile.respond_to?(:key?) && profile.respond_to?(:[])

          keys.each do |key|
            return profile[key] if profile.key?(key)
          end
          nil
        end
      end
    end
  end
end
