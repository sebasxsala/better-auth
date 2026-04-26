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
    end

    auth = described_class.auth

    expect(auth.options.secret).to eq("test-secret-that-is-long-enough-for-validation")
    expect(auth.options.base_url).to eq("https://app.example.com")
    expect(auth.options.plugins.map(&:id)).to eq(["rails-config"])
    expect(auth.options.trusted_origins).to eq(["https://app.example.com"])
    expect(auth.options.hooks).to eq(after: [after_hook])
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
