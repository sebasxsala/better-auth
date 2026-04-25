# frozen_string_literal: true

require "securerandom"
require "uri"

module BetterAuth
  class Configuration
    DEFAULT_BASE_PATH = "/api/auth"
    DEFAULT_SECRET = "better-auth-secret-12345678901234567890"
    DEFAULT_SESSION = {
      update_age: 24 * 60 * 60,
      expires_in: 60 * 60 * 24 * 7,
      fresh_age: 60 * 60 * 24
    }.freeze
    DEFAULT_EMAIL_AND_PASSWORD = {
      min_password_length: 8,
      max_password_length: 128
    }.freeze
    DEFAULT_STATELESS_SESSION = {
      cookie_cache: {
        enabled: true,
        strategy: "jwe",
        refresh_cache: true
      }
    }.freeze
    DEFAULT_STATELESS_ACCOUNT = {
      store_state_strategy: "cookie",
      store_account_cookie: true
    }.freeze

    attr_reader :app_name,
      :base_url,
      :base_path,
      :context_base_url,
      :secret,
      :database,
      :plugins,
      :trusted_origins,
      :rate_limit,
      :session,
      :account,
      :user,
      :verification,
      :advanced,
      :email_and_password,
      :social_providers,
      :secondary_storage,
      :database_hooks,
      :hooks,
      :disabled_paths,
      :trusted_origins_callback,
      :logger

    def initialize(options = {})
      options = symbolize_keys(options)

      @logger = options[:logger]
      @app_name = options[:app_name] || "Better Auth"
      @base_path = normalize_base_path(options.fetch(:base_path, DEFAULT_BASE_PATH))
      @database = options[:database]
      @secondary_storage = options[:secondary_storage]
      @plugins = normalize_plugins(options[:plugins])
      @advanced = deep_merge({}, symbolize_keys(options[:advanced] || {}))
      @disabled_paths = Array(options[:disabled_paths]).compact.map(&:to_s)
      @database_hooks = options[:database_hooks]
      @hooks = options[:hooks]
      @social_providers = symbolize_keys(options[:social_providers] || {})
      @trusted_origins_callback = options[:trusted_origins] if options[:trusted_origins].respond_to?(:call)
      @secret = resolve_secret(options)
      @base_url, @context_base_url = normalize_base_url(options[:base_url])
      @session = normalize_session(options[:session])
      @account = normalize_account(options[:account])
      @user = symbolize_keys(options[:user] || {})
      @verification = symbolize_keys(options[:verification] || {})
      @email_and_password = normalize_email_and_password(options[:email_and_password])
      @rate_limit = normalize_rate_limit(options[:rate_limit])
      @trusted_origins = normalize_trusted_origins(options[:trusted_origins])

      validate_secret
    end

    def trusted_origin?(url, allow_relative_paths: false)
      trusted_origins.any? do |origin|
        self.class.matches_origin_pattern?(url, origin, allow_relative_paths: allow_relative_paths)
      end
    end

    def to_h
      {
        app_name: app_name,
        base_url: base_url,
        base_path: base_path,
        secret: secret,
        database: database,
        plugins: plugins,
        trusted_origins: trusted_origins,
        rate_limit: rate_limit,
        session: session,
        account: account,
        user: user,
        verification: verification,
        advanced: advanced,
        email_and_password: email_and_password,
        social_providers: social_providers,
        secondary_storage: secondary_storage,
        database_hooks: database_hooks,
        hooks: hooks,
        disabled_paths: disabled_paths
      }
    end

    def self.matches_origin_pattern?(url, pattern, allow_relative_paths: false)
      return relative_path_allowed?(url) if url.start_with?("/") && allow_relative_paths
      return false if url.start_with?("/")

      uri = parse_uri(url)
      return false unless uri

      if pattern.include?("*") || pattern.include?("?")
        return wildcard_match?(pattern, origin_for(uri) || url) if pattern.include?("://")

        return wildcard_match?(pattern, uri.host.to_s)
      end

      protocol = uri.scheme&.then { |scheme| "#{scheme}:" }
      if protocol == "http:" || protocol == "https:" || protocol.nil?
        pattern == origin_for(uri)
      else
        url.start_with?(pattern)
      end
    end

    def self.relative_path_allowed?(url)
      %r{\A/(?!/|\\|%2f|%5c)[\w\-.+/@]*(?:\?[\w\-.+/=&%@]*)?\z}i.match?(url)
    end

    def self.parse_uri(url)
      URI.parse(url)
    rescue URI::InvalidURIError
      nil
    end

    def self.origin_for(uri)
      return nil unless uri.scheme && uri.host

      port = uri.port
      default_port = (uri.scheme == "http" && port == 80) || (uri.scheme == "https" && port == 443)
      host = uri.host
      host = "[#{host}]" if host.include?(":") && !host.start_with?("[")
      origin = "#{uri.scheme}://#{host}"
      default_port ? origin : "#{origin}:#{port}"
    end

    def self.wildcard_match?(pattern, value)
      regex = Regexp.escape(pattern).gsub("\\*", ".*").gsub("\\?", ".")
      /\A#{regex}\z/.match?(value)
    end

    private

    def normalize_base_url(value)
      configured = value || env_base_url
      return ["", ""] unless configured && !configured.empty?

      with_path = append_base_path(configured.to_s)
      uri = URI.parse(with_path)
      validate_http_url!(uri, configured)
      [self.class.origin_for(uri), with_path.sub(%r{/+\z}, "")]
    rescue URI::InvalidURIError
      raise Error, "Invalid base URL: #{configured}. Please provide a valid base URL."
    end

    def normalize_base_path(value)
      return "" if value.nil? || value == "" || value == "/"

      path = value.to_s
      path.start_with?("/") ? path.sub(%r{/+\z}, "") : "/#{path.sub(%r{/+\z}, "")}"
    end

    def append_base_path(url)
      uri = URI.parse(url)
      validate_http_url!(uri, url)
      path = uri.path.to_s.sub(%r{/+\z}, "")
      has_path = !path.empty? && path != "/"
      trimmed = url.to_s.sub(%r{/+\z}, "")
      return trimmed if has_path || base_path.empty?

      "#{trimmed}#{base_path}"
    end

    def validate_http_url!(uri, original)
      return if uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)

      raise Error, "Invalid base URL: #{original}. URL must include 'http://' or 'https://'"
    end

    def env_base_url
      base_url = ENV["BASE_URL"]
      [
        ENV["BETTER_AUTH_URL"],
        ENV["NEXT_PUBLIC_BETTER_AUTH_URL"],
        ENV["PUBLIC_BETTER_AUTH_URL"],
        ENV["NUXT_PUBLIC_BETTER_AUTH_URL"],
        ENV["NUXT_PUBLIC_AUTH_URL"],
        (base_url unless base_url == "/")
      ].find { |value| value && !value.empty? }
    end

    def resolve_secret(options)
      options[:secret] || ENV["BETTER_AUTH_SECRET"] || ENV["AUTH_SECRET"] || (test_environment? ? DEFAULT_SECRET : nil)
    end

    def validate_secret
      if secret.nil? || secret.empty?
        raise Error, "BETTER_AUTH_SECRET is missing. Set it in your environment or pass `secret` to BetterAuth.auth(secret: ...)."
      end

      return if test_environment? && secret == DEFAULT_SECRET

      warn("[better-auth] Warning: your BETTER_AUTH_SECRET should be at least 32 characters long for adequate security.") if secret.length < 32
      warn("[better-auth] Warning: your BETTER_AUTH_SECRET appears low-entropy. Use a randomly generated secret for production.") if entropy(secret) < 120
    end

    def entropy(value)
      unique = value.chars.uniq.length
      return 0 if unique.zero?

      Math.log2(unique**value.length)
    end

    def normalize_session(value)
      configured = symbolize_keys(value || {})
      cookie_cache = symbolize_keys(configured.delete(:cookie_cache) || {})
      session = deep_merge(DEFAULT_SESSION, configured)

      if database.nil?
        session = deep_merge(session, DEFAULT_STATELESS_SESSION)
      else
        session[:cookie_cache] = cookie_cache unless cookie_cache.empty?
      end

      session[:cookie_cache] = deep_merge(session[:cookie_cache] || {}, cookie_cache) unless cookie_cache.empty?
      session
    end

    def normalize_account(value)
      configured = symbolize_keys(value || {})
      database.nil? ? deep_merge(DEFAULT_STATELESS_ACCOUNT, configured) : configured
    end

    def normalize_email_and_password(value)
      deep_merge(DEFAULT_EMAIL_AND_PASSWORD, symbolize_keys(value || {}))
    end

    def normalize_rate_limit(value)
      configured = symbolize_keys(value || {})
      {
        enabled: configured.key?(:enabled) ? configured[:enabled] : production_environment?,
        window: configured[:window] || 10,
        max: configured[:max] || 100,
        storage: configured[:storage] || (secondary_storage ? "secondary-storage" : "memory")
      }.merge(configured)
    end

    def normalize_plugins(value)
      Array(value).compact.reject { |plugin| plugin == false }.map { |plugin| symbolize_keys(plugin) }
    end

    def normalize_trusted_origins(value)
      origins = []
      origins << base_url unless base_url.nil? || base_url.empty?
      origins.concat(Array(value).compact) unless value.respond_to?(:call)
      origins.concat(env_trusted_origins)
      origins.map(&:to_s).reject(&:empty?).uniq
    end

    def env_trusted_origins
      ENV.fetch("BETTER_AUTH_TRUSTED_ORIGINS", "").split(",").map(&:strip).reject(&:empty?)
    end

    def symbolize_keys(value)
      return value unless value.is_a?(Hash)

      value.each_with_object({}) do |(key, object_value), result|
        normalized_key = normalize_key(key)
        result[normalized_key] = object_value.is_a?(Hash) ? symbolize_keys(object_value) : object_value
      end
    end

    def normalize_key(key)
      key.to_s
        .gsub(/([a-z\d])([A-Z])/, "\\1_\\2")
        .tr("-", "_")
        .downcase
        .to_sym
    end

    def deep_merge(base, override)
      base.merge(override) do |_key, old_value, new_value|
        if old_value.is_a?(Hash) && new_value.is_a?(Hash)
          deep_merge(old_value, new_value)
        else
          new_value
        end
      end
    end

    def warn(message)
      if logger.respond_to?(:call)
        logger.call(:warn, message)
      elsif logger.respond_to?(:warn)
        logger.warn(message)
      end
    end

    def test_environment?
      ENV["RACK_ENV"] == "test" || ENV["RAILS_ENV"] == "test" || ENV["APP_ENV"] == "test"
    end

    def production_environment?
      ENV["RACK_ENV"] == "production" || ENV["RAILS_ENV"] == "production" || ENV["APP_ENV"] == "production"
    end
  end
end
