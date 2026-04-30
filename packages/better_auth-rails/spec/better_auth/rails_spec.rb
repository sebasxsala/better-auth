# frozen_string_literal: true

require_relative "../spec_helper"

RSpec.describe BetterAuth::Rails do
  after do
    described_class.instance_variable_set(:@auth, nil)
    described_class.instance_variable_set(:@configuration, nil)
  end

  it "has a version number" do
    expect(BetterAuth::Rails::VERSION).not_to be nil
  end

  it "round-trips Rails configuration into BetterAuth.auth options" do
    plugin = BetterAuth::Plugin.new(id: "rails-config")
    after_hook = ->(_ctx) {}

    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.base_url = "https://app.example.com"
      config.base_path = "/api/auth"
      config.database = :memory
      config.plugins = [plugin]
      config.trusted_origins = ["https://app.example.com"]
      config.hooks = {after: [after_hook]}
      config.password_hasher = :bcrypt
    end

    auth = described_class.auth

    expect(auth.options.secret).to eq("test-secret-that-is-long-enough-for-validation")
    expect(auth.options.base_url).to eq("https://app.example.com")
    expect(auth.options.plugins.map(&:id)).to eq(["rails-config"])
    expect(auth.options.trusted_origins).to eq(["https://app.example.com"])
    expect(auth.options.hooks).to eq(after: [after_hook])
    expect(auth.options.password_hasher).to eq(:bcrypt)
  end

  it "passes session advanced experimental and social provider options to core auth" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.session = {cookie_cache: {enabled: true, max_age: 300, strategy: "jwe"}}
      config.advanced = {ip_address: {ip_address_headers: ["x-client-ip"]}}
      config.experimental = {joins: true}
      config.social_providers = {github: {client_id: "id", client_secret: "secret"}}
    end

    auth = described_class.auth

    expect(auth.options.session[:cookie_cache]).to include(enabled: true, max_age: 300, strategy: "jwe")
    expect(auth.options.advanced[:ip_address][:ip_address_headers]).to eq(["x-client-ip"])
    expect(auth.options.experimental).to eq(joins: true)
    expect(auth.options.social_providers[:github]).to include(client_id: "id")
  end

  it "builds nested option hashes from Rails-style configuration blocks" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory

      config.email_and_password do |auth|
        auth.enabled = true
        auth.require_email_verification = true
      end

      config.email_verification do |email|
        email.send_on_sign_up = true
        email.send_on_sign_in = true
      end

      config.session do |session|
        session.cookie_cache do |cookie|
          cookie.enabled = true
          cookie.max_age = 300
          cookie.strategy = "jwe"
        end
      end
    end

    auth = described_class.auth

    expect(auth.options.email_and_password).to include(enabled: true, require_email_verification: true)
    expect(auth.options.email_verification).to include(send_on_sign_up: true, send_on_sign_in: true)
    expect(auth.options.session[:cookie_cache]).to include(enabled: true, max_age: 300, strategy: "jwe")
  end

  it "merges configuration blocks into existing hash values" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.session = {cookie_cache: {enabled: true, strategy: "jwe"}}

      config.session do |session|
        session.cookie_cache do |cookie|
          cookie.max_age = 600
        end
      end
    end

    auth = described_class.auth

    expect(auth.options.session[:cookie_cache]).to include(enabled: true, strategy: "jwe", max_age: 600)
  end

  it "keeps hash assignment compatible with block-enabled options" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.email_and_password = {enabled: true}
      config.session = {cookie_cache: {enabled: true, max_age: 300, strategy: "jwe"}}
    end

    auth = described_class.auth

    expect(auth.options.email_and_password).to include(enabled: true)
    expect(auth.options.session[:cookie_cache]).to include(enabled: true, max_age: 300, strategy: "jwe")
  end

  it "maps database_adapter active_record to the Rails ActiveRecord adapter" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database_adapter = :active_record
    end

    database = described_class.configuration.to_auth_options.fetch(:database)

    expect(database).to respond_to(:call)
    expect(database.call(BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory))).to be_a(BetterAuth::Rails::ActiveRecordAdapter)
  end

  it "rejects unsupported database_adapter aliases with guidance" do
    expect do
      described_class.configure do |config|
        config.database_adapter = :sequel
      end
    end.to raise_error(ArgumentError, /config\.database/)
  end

  it "uses a bare ActiveRecordAdapter instance as a callable database factory" do
    adapter_factory = BetterAuth::Rails::ActiveRecordAdapter.new
    options = BetterAuth::Configuration.new(secret: "test-secret-that-is-long-enough-for-validation", database: :memory)

    adapter = adapter_factory.call(options)

    expect(adapter).to be_a(BetterAuth::Rails::ActiveRecordAdapter)
    expect(adapter.options).to eq(options)
  end

  it "builds override auth instances without replacing the cached default auth" do
    described_class.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.base_path = "/api/auth"
      config.database = :memory
    end

    default_auth = described_class.auth
    custom_auth = described_class.auth(base_path: "/auth")

    expect(default_auth.options.base_path).to eq("/api/auth")
    expect(custom_auth.options.base_path).to eq("/auth")
    expect(described_class.auth).to eq(default_auth)
  end
end
