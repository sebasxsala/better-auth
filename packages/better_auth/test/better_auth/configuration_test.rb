# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthConfigurationTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_default_configuration_matches_upstream_defaults
    config = BetterAuth::Configuration.new(secret: SECRET)

    assert_equal "/api/auth", config.base_path
    assert_equal 24 * 60 * 60, config.session[:update_age]
    assert_equal 60 * 60 * 24 * 7, config.session[:expires_in]
    assert_equal 60 * 60 * 24, config.session[:fresh_age]
    assert_equal 8, config.email_and_password[:min_password_length]
    assert_equal 128, config.email_and_password[:max_password_length]
    assert_equal :scrypt, config.password_hasher
    assert_equal "cookie", config.account[:store_state_strategy]
    assert_equal true, config.account[:store_account_cookie]
    assert_equal({enabled: true, strategy: "jwe", refresh_cache: true}, config.session[:cookie_cache])
  end

  def test_secondary_storage_selects_secondary_rate_limit_storage_by_default
    storage = Object.new
    config = BetterAuth::Configuration.new(secret: SECRET, secondary_storage: storage)

    assert_equal "secondary-storage", config.rate_limit[:storage]
  end

  def test_secondary_storage_disables_cookie_refresh_cache
    storage = Object.new

    capture_io do
      @config = BetterAuth::Configuration.new(
        secret: SECRET,
        secondary_storage: storage,
        session: {cookie_cache: {refresh_cache: true}}
      )
    end

    assert_equal false, @config.session.dig(:cookie_cache, :refresh_cache)
  ensure
    remove_instance_variable(:@config) if defined?(@config)
  end

  def test_explicit_configuration_normalizes_ruby_option_names
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      base_path: "/custom-path",
      secret: SECRET,
      trusted_origins: ["http://example.com"],
      session: {
        update_age: 1000,
        expires_in: 2000,
        fresh_age: 0
      },
      email_and_password: {
        enabled: true,
        min_password_length: 12,
        max_password_length: 256
      },
      password_hasher: :bcrypt
    )

    assert_equal "http://localhost:3000", config.base_url
    assert_equal "http://localhost:3000/custom-path", config.context_base_url
    assert_equal "/custom-path", config.base_path
    assert_equal ["http://localhost:3000", "http://example.com"], config.trusted_origins
    assert_equal 1000, config.session[:update_age]
    assert_equal 2000, config.session[:expires_in]
    assert_equal 0, config.session[:fresh_age]
    assert_equal 12, config.email_and_password[:min_password_length]
    assert_equal 256, config.email_and_password[:max_password_length]
    assert_equal :bcrypt, config.password_hasher
  end

  def test_rejects_unknown_password_hasher
    error = assert_raises(BetterAuth::Error) do
      BetterAuth::Configuration.new(secret: SECRET, password_hasher: :argon2)
    end

    assert_includes error.message, "Unsupported password hasher"
  end

  def test_base_url_with_existing_path_keeps_that_path_and_extracts_origin_for_options
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000/some/path?query=value",
      secret: SECRET
    )

    assert_equal "http://localhost:3000", config.base_url
    assert_equal "http://localhost:3000/some/path?query=value", config.context_base_url
  end

  def test_secret_resolution_prefers_options_then_environment
    with_env("BETTER_AUTH_SECRET" => "env-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new(secret: SECRET)

      assert_equal SECRET, config.secret
    end

    with_env("BETTER_AUTH_SECRET" => "env-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new

      assert_equal "env-secret-that-is-long-enough-for-validation", config.secret
    end

    with_env("BETTER_AUTH_SECRET" => nil, "AUTH_SECRET" => "auth-secret-that-is-long-enough-for-validation") do
      config = BetterAuth::Configuration.new

      assert_equal "auth-secret-that-is-long-enough-for-validation", config.secret
    end
  end

  def test_missing_secret_fails_outside_tests
    with_env("BETTER_AUTH_SECRET" => nil, "AUTH_SECRET" => nil, "RACK_ENV" => "production") do
      error = assert_raises(BetterAuth::Error) { BetterAuth::Configuration.new }

      assert_match "BETTER_AUTH_SECRET is missing", error.message
    end
  end

  def test_short_or_low_entropy_secret_warns
    warnings = []

    BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      secret: "aaaaaaaa",
      logger: ->(level, message) { warnings << [level, message] }
    )

    assert warnings.any? { |level, message| level == :warn && message.include?("at least 32 characters") }
    assert warnings.any? { |level, message| level == :warn && message.include?("low-entropy") }
  end

  def test_trusted_origin_matching_matches_upstream_core_cases
    config = BetterAuth::Configuration.new(
      base_url: "http://localhost:3000",
      secret: SECRET,
      trusted_origins: ["https://trusted.com", "*.my-site.com", "https://*.protocol-site.com"]
    )

    assert config.trusted_origin?("http://localhost:3000/some/path")
    assert config.trusted_origin?("https://trusted.com/some/path")
    assert config.trusted_origin?("https://sub-domain.my-site.com/callback")
    assert config.trusted_origin?("https://api.protocol-site.com")
    refute config.trusted_origin?("https://trusted.com.malicious.com")
    refute config.trusted_origin?("http://sub-domain.trusted.com")
    refute config.trusted_origin?("http://api.protocol-site.com")
    refute config.trusted_origin?("/")
    assert config.trusted_origin?("/dashboard?email=123@email.com", allow_relative_paths: true)
    refute config.trusted_origin?("//evil.com", allow_relative_paths: true)
  end

  def test_plugin_list_normalization_filters_nil_and_preserves_order
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      plugins: [
        nil,
        {id: "first"},
        false,
        {id: "second"}
      ]
    )

    assert_equal ["first", "second"], config.plugins.map { |plugin| plugin[:id] }
  end

  def test_experimental_joins_option_accepts_camel_and_snake_case
    camel = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: true})
    snake = BetterAuth::Configuration.new(secret: SECRET, experimental: {joins: false})

    assert_equal({joins: true}, camel.experimental)
    assert_equal({joins: false}, snake.experimental)
  end

  def test_context_exposes_runtime_fields_and_new_session_mutator
    auth = BetterAuth.auth(base_url: "http://localhost:3000", secret: SECRET)
    context = auth.context

    assert_equal "Better Auth", context.app_name
    assert_equal "http://localhost:3000/api/auth", context.base_url
    assert_equal SECRET, context.secret
    assert_equal auth.options, context.options
    assert_nil context.current_session
    assert_nil context.new_session

    session = {id: "test-session", user_id: "user-1"}
    context.set_new_session(session)

    assert_equal session, context.new_session
  end

  private

  def with_env(values)
    previous = values.keys.to_h { |key| [key, ENV[key]] }
    values.each do |key, value|
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end

    yield
  ensure
    previous.each do |key, value|
      if value.nil?
        ENV.delete(key)
      else
        ENV[key] = value
      end
    end
  end
end
