# frozen_string_literal: true

require "net/http"
require "openssl"
require "uri"

module BetterAuth
  module Plugins
    HAVE_I_BEEN_PWNED_ERROR_CODES = {
      "PASSWORD_COMPROMISED" => "The password you entered has been compromised. Please choose a different password."
    }.freeze

    HAVE_I_BEEN_PWNED_DEFAULT_PATHS = [
      "/sign-up/email",
      "/change-password",
      "/reset-password"
    ].freeze

    module_function

    def have_i_been_pwned(options = {})
      config = normalize_hash(options)
      config[:paths] = Array(config[:paths]).empty? ? HAVE_I_BEEN_PWNED_DEFAULT_PATHS : Array(config[:paths])

      Plugin.new(
        id: "haveIBeenPwned",
        hooks: {
          before: [
            {
              matcher: ->(ctx) { config[:paths].include?(ctx.path) },
              handler: ->(ctx) { have_i_been_pwned_check_context!(ctx, config) }
            }
          ]
        },
        error_codes: HAVE_I_BEEN_PWNED_ERROR_CODES,
        options: config
      )
    end

    def have_i_been_pwned_check_context!(ctx, config)
      body = normalize_hash(ctx.body)
      password = case ctx.path
      when "/sign-up/email"
        body[:password]
      when "/change-password", "/reset-password"
        body[:new_password]
      else
        body[:password] || body[:new_password]
      end
      have_i_been_pwned_check_password!(password, config)
      nil
    end

    def have_i_been_pwned_check_password!(password, config)
      return if password.to_s.empty?

      hash = OpenSSL::Digest.hexdigest("SHA1", password.to_s).upcase
      prefix = hash[0, 5]
      suffix = hash[5..]
      data = if config[:range_lookup].respond_to?(:call)
        config[:range_lookup].call(prefix)
      else
        have_i_been_pwned_range_lookup(prefix)
      end

      found = data.to_s.lines.any? { |line| line.split(":").first.to_s.upcase == suffix }
      return unless found

      raise APIError.new(
        "BAD_REQUEST",
        message: config[:custom_password_compromised_message] || HAVE_I_BEEN_PWNED_ERROR_CODES["PASSWORD_COMPROMISED"],
        code: "PASSWORD_COMPROMISED"
      )
    rescue APIError
      raise
    rescue
      raise APIError.new("INTERNAL_SERVER_ERROR", message: "Failed to check password. Please try again later.")
    end

    def have_i_been_pwned_range_lookup(prefix)
      uri = URI.parse("https://api.pwnedpasswords.com/range/#{prefix}")
      request = Net::HTTP::Get.new(uri)
      request["Add-Padding"] = "true"
      request["User-Agent"] = "BetterAuth Password Checker"
      response = Net::HTTP.start(uri.host, uri.port, use_ssl: true) { |http| http.request(request) }
      unless response.is_a?(Net::HTTPSuccess)
        raise APIError.new("INTERNAL_SERVER_ERROR", message: "Failed to check password. Status: #{response.code}")
      end

      response.body.to_s
    end
  end
end
