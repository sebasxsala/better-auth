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

  def test_store_session_in_database_keeps_hooked_db_copy_and_falls_back_when_secondary_storage_misses
    storage = MemoryStorage.new
    internal = internal_adapter(
      secondary_storage: storage,
      session: {store_session_in_database: true},
      database_hooks: {
        session: {
          create: {
            before: ->(_data, _context) { {data: {userAgent: "from-hook"}} }
          }
        }
      }
    )
    user = internal.create_user(name: "Ada", email: "ada@example.com")

    session = internal.create_session(user["id"], false, {token: "token-db"}, true)
    stored_db_session = internal.adapter.find_one(model: "session", where: [{field: "token", value: "token-db"}])

    assert_equal "from-hook", session["userAgent"]
    assert_equal "from-hook", stored_db_session["userAgent"]

    storage.delete("token-db")
    found = internal.find_session("token-db")

    assert_equal "token-db", found[:session]["token"]
    assert_equal user["id"], found[:user]["id"]
  end

  def test_update_session_with_secondary_storage_updates_database_copy_when_enabled
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage, session: {store_session_in_database: true})
    user = internal.create_user(name: "Ada", email: "ada@example.com")
    internal.create_session(user["id"], false, {token: "token-update"}, true)

    internal.update_session("token-update", {userAgent: "updated-agent"})
    stored_db_session = internal.adapter.find_one(model: "session", where: [{field: "token", value: "token-update"}])

    assert_equal "updated-agent", internal.find_session("token-update")[:session]["userAgent"]
    assert_equal "updated-agent", stored_db_session["userAgent"]
  end

  def test_list_sessions_deduplicates_secondary_storage_active_session_tokens
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage)
    user = internal.create_user(name: "Ada", email: "ada@example.com")
    session = internal.create_session(user["id"], false, {token: "token-dup"}, true)
    expires_ms = (session["expiresAt"].to_f * 1000).to_i

    storage.set("active-sessions-#{user["id"]}", JSON.generate([
      {"token" => "token-dup", "expiresAt" => expires_ms},
      {"token" => "token-dup", "expiresAt" => expires_ms}
    ]), 60)

    assert_equal ["token-dup"], internal.list_sessions(user["id"]).map { |entry| entry["token"] }
  end

  def test_list_sessions_skips_missing_and_corrupt_secondary_storage_entries
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage)
    user = internal.create_user(name: "Ada", email: "ada@example.com")
    session = internal.create_session(user["id"], false, {token: "token-valid"}, true)
    expires_ms = (session["expiresAt"].to_f * 1000).to_i
    storage.set("token-corrupt", "{bad-json", 60)
    storage.set("active-sessions-#{user["id"]}", JSON.generate([
      {"token" => "token-valid", "expiresAt" => expires_ms},
      {"token" => "token-missing", "expiresAt" => expires_ms},
      {"token" => "token-corrupt", "expiresAt" => expires_ms}
    ]), 60)

    assert_equal ["token-valid"], internal.list_sessions(user["id"]).map { |entry| entry["token"] }
    assert_equal ["token-valid"], internal.find_sessions(["token-valid", "token-corrupt"]).map { |entry| entry[:session]["token"] }
  end

  def test_find_session_uses_adapter_join_when_experimental_joins_enabled
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, experimental: {joins: true})
    adapter = BetterAuth::Adapters::Memory.new(config)
    internal = BetterAuth::Adapters::InternalAdapter.new(adapter, config)
    user = internal.create_user("name" => "Ada", "email" => "ada@example.com")
    session = internal.create_session(user["id"])

    found = internal.find_session(session["token"])

    assert_equal session["token"], found[:session]["token"]
    assert_equal user["id"], found[:user]["id"]
  end

  def test_find_session_falls_back_to_separate_queries_when_experimental_joins_disabled
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, experimental: {joins: false})
    adapter = BetterAuth::Adapters::Memory.new(config)
    internal = BetterAuth::Adapters::InternalAdapter.new(adapter, config)
    user = internal.create_user("name" => "Ada", "email" => "ada@example.com")
    session = internal.create_session(user["id"])

    found = internal.find_session(session["token"])

    assert_equal session["token"], found[:session]["token"]
    assert_equal user["id"], found[:user]["id"]
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

  def test_verification_values_use_secondary_storage_by_default
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage)
    expires_at = Time.now + 120

    verification = internal.create_verification_value(identifier: "verify-secondary", value: "initial", expiresAt: expires_at)

    assert verification["id"]
    assert_empty internal.adapter.find_many(model: "verification")
    stored = JSON.parse(storage.get("verification:verify-secondary"))
    assert_equal verification["id"], stored.fetch("id")
    assert_equal "initial", stored.fetch("value")
    assert_in_delta 120, storage.ttls.fetch("verification:verify-secondary"), 2

    assert_equal "initial", internal.find_verification_value("verify-secondary")["value"]

    internal.update_verification_value(verification["id"], value: "updated")
    assert_equal "updated", internal.find_verification_value("verify-secondary")["value"]

    internal.delete_verification_value(verification["id"])
    assert_nil storage.get("verification:verify-secondary")
  end

  def test_verification_store_in_database_falls_back_when_secondary_storage_misses
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage, verification: {store_in_database: true})

    verification = internal.create_verification_value(identifier: "verify-dual", value: "initial", expiresAt: Time.now + 120)

    assert storage.get("verification:verify-dual")
    assert_equal verification["id"], internal.adapter.find_many(model: "verification").first["id"]

    storage.delete("verification:verify-dual")
    found = internal.find_verification_value("verify-dual")

    assert_equal verification["id"], found["id"]
    assert_equal "initial", found["value"]
  end

  def test_verification_secondary_storage_hashes_identifiers_when_configured
    storage = MemoryStorage.new
    internal = internal_adapter(secondary_storage: storage, verification: {store_identifier: "hashed"})
    hashed = BetterAuth::Crypto.sha256("verify-hashed", encoding: :base64url)

    verification = internal.create_verification_value(identifier: "verify-hashed", value: "secret", expiresAt: Time.now + 120)

    assert_nil storage.get("verification:verify-hashed")
    assert storage.get("verification:#{hashed}")
    assert_equal hashed, verification["identifier"]
    assert_equal "secret", internal.find_verification_value("verify-hashed")["value"]
  end

  def test_verification_secondary_storage_supports_identifier_overrides
    storage = MemoryStorage.new
    internal = internal_adapter(
      secondary_storage: storage,
      verification: {
        store_identifier: {
          default: "plain",
          overrides: {
            "custom:" => {hash: ->(identifier) { "stored-#{identifier.delete_prefix("custom:")}" }}
          }
        }
      }
    )

    internal.create_verification_value(identifier: "custom:token", value: "secret", expiresAt: Time.now + 120)
    internal.create_verification_value(identifier: "plain:token", value: "visible", expiresAt: Time.now + 120)

    assert storage.get("verification:stored-token")
    assert storage.get("verification:plain:token")
    assert_equal "secret", internal.find_verification_value("custom:token")["value"]
    assert_equal "visible", internal.find_verification_value("plain:token")["value"]
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
