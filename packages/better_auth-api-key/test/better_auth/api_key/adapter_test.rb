# frozen_string_literal: true

require_relative "test_support"

class BetterAuthAPIKeyAdapterTest < Minitest::Test
  include APIKeyTestSupport

  def test_storage_key_builders_match_upstream_layout
    assert_equal "api-key:hashed", BetterAuth::APIKey::Adapter.storage_key_by_hash("hashed")
    assert_equal "api-key:by-id:key-id", BetterAuth::APIKey::Adapter.storage_key_by_id("key-id")
    assert_equal "api-key:by-ref:user-id", BetterAuth::APIKey::Adapter.storage_key_by_reference("user-id")
  end

  def test_storage_record_serializes_and_deserializes_times
    now = Time.now
    record = {
      "id" => "key-id",
      "createdAt" => now,
      "updatedAt" => now,
      "expiresAt" => now,
      "lastRefillAt" => now,
      "lastRequest" => now
    }

    serialized = BetterAuth::APIKey::Adapter.storage_record(record)
    restored = BetterAuth::APIKey::Adapter.deserialize_record(serialized.dup)

    assert_instance_of String, serialized.fetch("createdAt")
    assert_instance_of Time, restored.fetch("createdAt")
    assert_instance_of Time, restored.fetch("lastRequest")
  end

  def test_secondary_storage_ttl_is_set_for_expiring_key
    storage = APIKeyTestSupport::MemoryStorage.new
    auth = build_api_key_auth(storage: "secondary-storage", secondary_storage: storage, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "adapter-storage-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {expiresIn: 60 * 60 * 24 + 1})

    assert_operator storage.ttls.fetch("api-key:by-id:#{created[:id]}"), :>, 0
  end

  def test_migrate_legacy_metadata_updates_double_stringified_database_value
    auth = build_api_key_auth(enable_metadata: true, default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "adapter-metadata-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {plan: "free"}})
    legacy_metadata = JSON.generate(JSON.generate({plan: "legacy"}))
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy_metadata})
    record = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])

    migrated = BetterAuth::APIKey::Adapter.migrate_legacy_metadata(auth, record, storage: "database")

    assert_equal JSON.generate({"plan" => "legacy"}), migrated.fetch("metadata")
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal({"plan" => "legacy"}, JSON.parse(stored.fetch("metadata")))
  end

  def test_migrate_legacy_metadata_leaves_null_and_object_values_unchanged
    auth = build_api_key_auth(enable_metadata: true, default_key_length: 12)
    null_record = {"id" => "null-metadata-key", "metadata" => nil}
    object_record = {"id" => "object-metadata-key", "metadata" => JSON.generate({"plan" => "pro"})}

    assert_same null_record, BetterAuth::APIKey::Adapter.migrate_legacy_metadata(auth, null_record, storage: "database")
    assert_equal object_record, BetterAuth::APIKey::Adapter.migrate_legacy_metadata(auth, object_record, storage: "database")
  end

  def test_custom_storage_takes_precedence_over_context_secondary_storage
    custom_storage = APIKeyTestSupport::MemoryStorage.new
    context_storage = APIKeyTestSupport::MemoryStorage.new
    auth = build_api_key_auth(
      storage: "secondary-storage",
      custom_storage: custom_storage,
      secondary_storage: context_storage,
      default_key_length: 12
    )
    cookie = sign_up_cookie(auth, email: "adapter-custom-storage-key@example.com")

    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})

    assert custom_storage.get("api-key:by-id:#{created[:id]}")
    assert_nil context_storage.get("api-key:by-id:#{created[:id]}")
  end

  def test_reference_list_helpers_add_remove_and_ignore_invalid_json
    storage = APIKeyTestSupport::MemoryStorage.new
    reference_key = BetterAuth::APIKey::Adapter.storage_key_by_reference("user-id")

    BetterAuth::APIKey::Adapter.ref_list_add(storage, reference_key, "first")
    BetterAuth::APIKey::Adapter.ref_list_add(storage, reference_key, "first")
    BetterAuth::APIKey::Adapter.ref_list_add(storage, reference_key, "second")
    assert_equal ["first", "second"], JSON.parse(storage.get(reference_key))

    BetterAuth::APIKey::Adapter.ref_list_remove(storage, reference_key, "first")
    assert_equal ["second"], JSON.parse(storage.get(reference_key))

    storage.set(reference_key, "{")
    assert_equal [], BetterAuth::APIKey::Adapter.safe_parse_id_list(storage.get(reference_key))
  end

  def test_list_for_reference_warns_on_corrupt_reference_index_json
    storage = APIKeyTestSupport::MemoryStorage.new
    ref = "user-corrupt"
    storage.set(BetterAuth::APIKey::Adapter.storage_key_by_reference(ref), "{bad")

    warnings = []
    logger = Object.new
    logger.define_singleton_method(:warn) { |msg| warnings << msg }

    auth = build_api_key_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: false,
      default_key_length: 12
    )
    auth.context.define_singleton_method(:logger) { logger }

    ctx = Struct.new(:context).new(auth.context)
    config = BetterAuth::APIKey::Configuration.normalize({})[:configurations].first
    config = config.merge(storage: "secondary-storage", fallback_to_database: false)

    result = BetterAuth::APIKey::Adapter.list_for_reference(ctx, ref, config)

    assert_equal [], result
    assert_equal 1, warnings.length
    assert_match(/Corrupt api-key reference index/i, warnings.first)
  end
end
