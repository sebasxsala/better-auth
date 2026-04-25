# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthInternalAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  MemoryStorage = Struct.new(:store, :ttls) do
    def initialize
      super({}, {})
    end

    def set(key, value, ttl = nil)
      store[key] = value
      ttls[key] = ttl if ttl
    end

    def get(key)
      store[key]
    end

    def delete(key)
      store.delete(key)
      ttls.delete(key)
    end
  end

  def test_auth_initializes_default_memory_and_internal_adapters
    auth = BetterAuth.auth(secret: SECRET)

    assert_instance_of BetterAuth::Adapters::Memory, auth.context.adapter
    assert_instance_of BetterAuth::Adapters::InternalAdapter, auth.context.internal_adapter
  end

  def test_create_oauth_user_and_find_oauth_user
    internal = internal_adapter

    result = internal.create_oauth_user(
      {email: "PERSON@example.com", name: "Person", emailVerified: true},
      {providerId: "github", accountId: "github-1", accessToken: "secret"}
    )

    assert_equal "person@example.com", result[:user]["email"]
    assert_equal result[:user]["id"], result[:account]["userId"]

    found = internal.find_oauth_user("PERSON@example.com", "github-1", "github")

    assert_equal result[:user], found[:user]
    assert_equal result[:account], found[:linked_account]
    assert_equal [result[:account]], found[:accounts]
  end

  def test_create_find_update_and_delete_session_with_secondary_storage
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage)
    user = internal.create_user(name: "Ada", email: "ada@example.com")

    session = internal.create_session(user["id"], false, {token: "token-1"}, true)
    active_key = "active-sessions-#{user["id"]}"

    assert_equal "token-1", session["token"]
    stored = JSON.parse(storage.get(active_key))
    assert_equal "token-1", stored.fetch(0).fetch("token")
    assert_in_delta session["expiresAt"].to_f * 1000, stored.fetch(0).fetch("expiresAt"), 10

    found = internal.find_session("token-1")
    assert_equal user["id"], found[:user]["id"]
    assert_equal "token-1", found[:session]["token"]

    internal.update_session("token-1", {userAgent: "new-agent"})
    assert_equal "new-agent", internal.find_session("token-1")[:session]["userAgent"]

    internal.delete_session("token-1")
    assert_nil storage.get(active_key)
    assert_nil internal.find_session("token-1")
  end

  def test_verification_lifecycle_runs_hooks_and_cleans_expired_values
    calls = []
    internal = internal_adapter(
      database_hooks: {
        verification: {
          create: {
            before: ->(data, _context) {
              calls << [:before_create, data["identifier"]]
              {data: data.merge("value" => "mutated")}
            },
            after: ->(data, _context) { calls << [:after_create, data["value"]] }
          },
          delete: {
            before: ->(data, _context) { calls << [:before_delete, data["identifier"]] },
            after: ->(data, _context) { calls << [:after_delete, data["identifier"]] }
          }
        }
      }
    )

    expired = internal.create_verification_value(identifier: "verify-1", value: "initial", expiresAt: Time.now - 60)

    assert_equal "mutated", expired["value"]
    assert_equal "verify-1", internal.find_verification_value("verify-1")["identifier"]
    assert_nil internal.find_verification_value("verify-1")
    assert_includes calls, [:before_create, "verify-1"]
    assert_includes calls, [:after_create, "mutated"]
    assert_includes calls, [:before_delete, "verify-1"]
    assert_includes calls, [:after_delete, "verify-1"]
  end

  def test_user_and_account_helpers
    internal = internal_adapter
    user = internal.create_user(name: "Ada", email: "ADA@example.com")
    credential = internal.create_account(userId: user["id"], providerId: "credential", accountId: user["id"], password: "old")
    social = internal.link_account(userId: user["id"], providerId: "github", accountId: "github-1")

    assert_equal user, internal.find_user_by_email("ada@example.com")[:user]
    assert_equal user, internal.find_user_by_id(user["id"])
    assert_equal 2, internal.find_accounts(user["id"]).length

    internal.update_password(user["id"], "new")
    assert_equal "new", internal.find_account_by_provider_id(credential["accountId"], "credential")["password"]

    internal.delete_account(social["id"])
    assert_nil internal.find_account_by_provider_id("github-1", "github")

    internal.delete_accounts(user["id"])
    assert_empty internal.find_accounts(user["id"])
  end

  private

  def internal_adapter(options = {})
    config = BetterAuth::Configuration.new({secret: SECRET, database: :memory}.merge(options))
    adapter = BetterAuth::Adapters::Memory.new(config)
    BetterAuth::Adapters::InternalAdapter.new(adapter, config)
  end
end
