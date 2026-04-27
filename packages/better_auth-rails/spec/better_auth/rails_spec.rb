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
