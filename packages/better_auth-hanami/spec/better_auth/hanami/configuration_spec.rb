# frozen_string_literal: true

require_relative "../../spec_helper"

RSpec.describe BetterAuth::Hanami do
  after do
    described_class.instance_variable_set(:@auth, nil)
    described_class.instance_variable_set(:@configuration, nil)
  end

  it "builds a core auth instance from Hanami configuration" do
    described_class.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_url = "http://localhost:2300"
      config.trusted_origins = ["http://localhost:2300"]
      config.email_and_password = {enabled: true}
    end

    auth = described_class.auth

    expect(auth).to be_a(BetterAuth::Auth)
    expect(auth.context.options.base_path).to eq("/api/auth")
    expect(auth.context.options.base_url).to eq("http://localhost:2300")
    expect(auth.context.options.trusted_origins).to eq(["http://localhost:2300"])
  end

  it "returns a fresh auth instance when overrides are provided" do
    described_class.configure do |config|
      config.secret = secret
      config.database = :memory
      config.base_path = "/api/auth"
    end

    default_auth = described_class.auth
    override_auth = described_class.auth(base_path: "/auth")

    expect(default_auth.context.options.base_path).to eq("/api/auth")
    expect(override_auth.context.options.base_path).to eq("/auth")
    expect(override_auth).not_to equal(default_auth)
  end

  def secret
    "test-secret-that-is-long-enough-for-validation"
  end
end
