# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthMemoryAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def setup
    @config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    @adapter = BetterAuth::Adapters::Memory.new(@config)
  end

  def test_create_applies_defaults_generates_ids_and_preserves_camel_case_fields
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ADA@example.com"})

    assert_kind_of String, user["id"]
    assert_equal "Ada", user["name"]
    assert_equal "ADA@example.com", user["email"]
    assert_equal false, user["emailVerified"]
    assert_nil user["image"]
    assert_kind_of Time, user["createdAt"]
    assert_kind_of Time, user["updatedAt"]
  end

  def test_find_many_supports_where_operators_sort_limit_offset_and_count
    3.times do |index|
      @adapter.create(model: "user", data: {
        id: "user-#{index}",
        name: "User #{index}",
        email: "user#{index}@example.com"
      }, force_allow_id: true)
    end

    matches = @adapter.find_many(
      model: "user",
      where: [{field: "id", operator: "in", value: ["user-0", "user-2"]}],
      sort_by: {field: "email", direction: "desc"},
      limit: 1,
      offset: 0
    )

    assert_equal ["user-2"], matches.map { |user| user["id"] }
    assert_equal 3, @adapter.count(model: "user", where: [{field: "email", operator: "contains", value: "@example.com"}])
  end

  def test_update_delete_many_and_transaction_rollback
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})

    updated = @adapter.update(model: "user", where: [{field: "id", value: user["id"]}], update: {name: "Grace"})

    assert_equal "Grace", updated["name"]

    assert_raises(RuntimeError) do
      @adapter.transaction do |trx|
        trx.update_many(model: "user", where: [], update: {name: "Rolled Back"})
        raise "boom"
      end
    end

    assert_equal "Grace", @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}])["name"]
    assert_equal 1, @adapter.delete_many(model: "user", where: [{field: "id", value: user["id"]}])
    assert_nil @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}])
  end

  def test_find_one_with_join_returns_related_user
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = @adapter.create(
      model: "session",
      data: {userId: user["id"], token: "token-1", expiresAt: Time.now + 60},
      force_allow_id: true
    )

    found = @adapter.find_one(model: "session", where: [{field: "token", value: session["token"]}], join: {user: true})

    assert_equal session["token"], found["token"]
    assert_equal user, found["user"]
  end
end
