# frozen_string_literal: true

module BetterAuth
  class SecretConfig
    ENVELOPE_PREFIX = "$ba$"

    attr_reader :keys, :current_version, :legacy_secret

    def initialize(keys:, current_version:, legacy_secret: nil)
      normalized_keys = keys.each_with_object({}) do |(version, value), result|
        result[normalize_version!(version)] = value.to_s
      end
      @keys = normalized_keys.freeze
      @current_version = normalize_version!(current_version)
      @legacy_secret = legacy_secret unless legacy_secret.to_s.empty?
    end

    def current_secret
      keys.fetch(current_version) do
        raise Error, "Secret version #{current_version} not found in keys"
      end
    end

    def all_secrets
      entries = keys.map { |version, value| [version, value] }
      entries << [-1, legacy_secret] if legacy_secret && !keys.value?(legacy_secret)
      entries
    end

    def self.parse_env(value)
      return nil if value.to_s.empty?

      value.to_s.split(",").map do |entry|
        entry = entry.strip
        colon_index = entry.index(":")
        raise Error, "Invalid BETTER_AUTH_SECRETS entry: \"#{entry}\". Expected format: \"<version>:<secret>\"" unless colon_index

        version = entry[0...colon_index].strip
        secret = entry[(colon_index + 1)..].to_s.strip
        raise Error, "Empty secret value for version #{version} in BETTER_AUTH_SECRETS." if secret.empty?

        {version: parse_version!(version, source: "BETTER_AUTH_SECRETS"), value: secret}
      end
    end

    def self.validate_secrets!(secrets, logger: nil)
      entries = Array(secrets)
      raise Error, "`secrets` array must contain at least one entry." if entries.empty?

      seen = {}
      entries.each do |entry|
        data = normalize_entry(entry)
        version = parse_version!(data.fetch(:version), source: "`secrets`")
        value = data.fetch(:value, nil).to_s
        raise Error, "Empty secret value for version #{version} in `secrets`." if value.empty?
        raise Error, "Duplicate version #{version} in `secrets`. Each version must be unique." if seen[version]

        seen[version] = true
      end

      current = normalize_entry(entries.first)
      current_version = parse_version!(current.fetch(:version), source: "`secrets`")
      current_value = current.fetch(:value).to_s
      warn(logger, "[better-auth] Warning: the current secret (version #{current_version}) should be at least 32 characters long for adequate security.") if current_value.length < 32
      warn(logger, "[better-auth] Warning: the current secret appears low-entropy. Use a randomly generated secret for production.") if entropy(current_value) < 120
    end

    def self.build(secrets, legacy_secret, logger: nil)
      validate_secrets!(secrets, logger: logger)
      entries = Array(secrets).map { |entry| normalize_entry(entry) }
      keys = entries.each_with_object({}) do |entry, result|
        result[parse_version!(entry.fetch(:version), source: "`secrets`")] = entry.fetch(:value).to_s
      end
      current_version = parse_version!(entries.first.fetch(:version), source: "`secrets`")
      legacy = (legacy_secret && legacy_secret != Configuration::DEFAULT_SECRET) ? legacy_secret : nil
      new(keys: keys, current_version: current_version, legacy_secret: legacy)
    end

    def self.normalize_entry(entry)
      raise Error, "Invalid `secrets` entry. Expected a hash with `version` and `value`." unless entry.is_a?(Hash)

      entry.each_with_object({}) do |(key, value), result|
        result[key.to_s.tr("-", "_").to_sym] = value
      end
    end

    def self.parse_version!(value, source:)
      text = value.to_s.strip
      unless text.match?(/\A(?:0|[1-9]\d*)\z/)
        raise Error, "Invalid version #{value} in #{source}. Version must be a non-negative integer."
      end

      text.to_i
    end

    def self.entropy(value)
      unique = value.to_s.chars.uniq.length
      return 0 if unique.zero?

      Math.log2(unique**value.to_s.length)
    end

    def self.warn(logger, message)
      if logger.respond_to?(:call)
        logger.call(:warn, message)
      elsif logger.respond_to?(:warn)
        logger.warn(message)
      end
    end

    def normalize_version!(version)
      self.class.parse_version!(version, source: "`secrets`")
    end
  end
end
