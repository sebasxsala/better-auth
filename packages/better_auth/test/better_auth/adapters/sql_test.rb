# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSQLAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_sql_adapter_uses_parameterized_crud_and_returns_logical_fields
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new(
      [{"id" => "user-1", "name" => "Ada", "email" => "ada@example.com", "email_verified" => false, "created_at" => Time.at(1), "updated_at" => Time.at(1)}],
      [{"id" => "user-1", "name" => "Ada", "email" => "ada@example.com", "email_verified" => false, "created_at" => Time.at(1), "updated_at" => Time.at(1)}],
      [{"count" => 1}]
    )
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    created = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    found = adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])
    count = adapter.count(model: "user", where: [{field: "email", operator: "contains", value: "@example.com"}])

    assert_equal "user-1", created["id"]
    assert_equal false, created["emailVerified"]
    assert_equal "ada@example.com", found["email"]
    assert_equal 1, count
    assert_includes connection.sql.first, 'INSERT INTO "users"'
    assert_includes connection.sql[1], 'WHERE "users"."email" = $1'
    assert_includes connection.sql[2], "LIKE $1"
    assert_equal ["user-1", "Ada", "ada@example.com", false], connection.params.first.first(4)
    assert_kind_of Time, connection.params.first[4]
    assert_kind_of Time, connection.params.first[5]
    assert_equal [["ada@example.com"], ["%@example.com%"]], connection.params.drop(1)
  end

  def test_sql_adapter_builds_join_queries_for_session_user_lookup
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([
      {
        "id" => "session-1",
        "expires_at" => Time.at(100),
        "token" => "token-1",
        "ip_address" => "127.0.0.1",
        "user_agent" => "test",
        "user_id" => "user-1",
        "created_at" => Time.at(1),
        "updated_at" => Time.at(1),
        "user__id" => "user-1",
        "user__name" => "Ada",
        "user__email" => "ada@example.com",
        "user__email_verified" => true,
        "user__image" => nil,
        "user__created_at" => Time.at(1),
        "user__updated_at" => Time.at(1)
      }
    ])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    found = adapter.find_one(model: "session", where: [{field: "token", value: "token-1"}], join: {user: true})

    assert_equal "token-1", found["token"]
    assert_equal "user-1", found["user"]["id"]
    assert_includes connection.sql.first, 'LEFT JOIN "users" AS "user" ON "user"."id" = "sessions"."user_id"'
  end

  def test_sql_adapter_coerces_database_output_types
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([
      {
        "id" => "user-1",
        "name" => "Ada",
        "email" => "ada@example.com",
        "email_verified" => "f",
        "created_at" => "2026-04-26 02:49:07.41301",
        "updated_at" => "2026-04-26 02:49:07.413012"
      }
    ])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    found = adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}])

    assert_equal false, found["emailVerified"]
    assert_kind_of Time, found["createdAt"]
    assert_kind_of Time, found["updatedAt"]
  end

  def test_sql_adapter_builds_user_account_collection_join
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([
      {
        "id" => "user-1",
        "name" => "Ada",
        "email" => "ada@example.com",
        "email_verified" => true,
        "image" => nil,
        "created_at" => Time.at(1),
        "updated_at" => Time.at(1),
        "account__id" => "account-1",
        "account__account_id" => "github-1",
        "account__provider_id" => "github",
        "account__user_id" => "user-1",
        "account__access_token" => "access-1",
        "account__refresh_token" => nil,
        "account__id_token" => nil,
        "account__access_token_expires_at" => nil,
        "account__refresh_token_expires_at" => nil,
        "account__scope" => "repo",
        "account__password" => nil,
        "account__created_at" => Time.at(1),
        "account__updated_at" => Time.at(1)
      },
      {
        "id" => "user-1",
        "name" => "Ada",
        "email" => "ada@example.com",
        "email_verified" => true,
        "image" => nil,
        "created_at" => Time.at(1),
        "updated_at" => Time.at(1),
        "account__id" => "account-2",
        "account__account_id" => "credential-1",
        "account__provider_id" => "credential",
        "account__user_id" => "user-1",
        "account__access_token" => nil,
        "account__refresh_token" => nil,
        "account__id_token" => nil,
        "account__access_token_expires_at" => nil,
        "account__refresh_token_expires_at" => nil,
        "account__scope" => nil,
        "account__password" => "hash",
        "account__created_at" => Time.at(1),
        "account__updated_at" => Time.at(1)
      }
    ])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    found = adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}], join: {account: true})

    assert_equal "ada@example.com", found["email"]
    assert_equal ["github", "credential"], found["account"].map { |account| account["providerId"] }
    assert_includes connection.sql.first, 'LEFT JOIN "accounts" AS "account" ON "account"."user_id" = "users"."id"'
    refute_includes connection.sql.first, "LIMIT"
  end

  def test_sql_adapter_honors_or_connectors_in_where_clauses
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    adapter.find_many(
      model: "user",
      where: [
        {field: "email", value: "ada@example.com"},
        {field: "name", connector: "OR", value: "Ada"}
      ]
    )

    assert_includes connection.sql.first, 'WHERE "users"."email" = $1 OR "users"."name" = $2'
    assert_equal [["ada@example.com", "Ada"]], connection.params
  end

  def test_sql_adapter_preserves_false_where_values
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])

    assert_includes connection.sql.first, 'WHERE "users"."email_verified" = $1'
    assert_equal [[false]], connection.params
  end

  def test_sql_adapter_uses_top_for_mssql_find_one
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :mssql)

    adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])

    assert_includes connection.sql.first, "SELECT TOP (1)"
    refute_includes connection.sql.first, "LIMIT"
  end

  def test_sql_adapter_rejects_input_false_fields_without_force_allow_id
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new([])
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :postgres)

    error = assert_raises(BetterAuth::APIError) do
      adapter.create(
        model: "user",
        data: {name: "Ada", email: "ada@example.com", emailVerified: true}
      )
    end

    assert_equal "emailVerified is not allowed to be set", error.message
  end

  def test_sql_adapter_update_returns_logical_record_for_non_returning_dialects
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = RecordingConnection.new(
      [{"id" => "user-1"}],
      [],
      [{"id" => "user-1", "name" => "Grace", "email" => "ada@example.com", "email_verified" => false, "created_at" => Time.at(1), "updated_at" => Time.at(2)}]
    )
    adapter = BetterAuth::Adapters::SQL.new(config, connection: connection, dialect: :sqlite)

    updated = adapter.update(model: "user", where: [{field: "id", value: "user-1"}], update: {name: "Grace"})

    assert_equal "Grace", updated["name"]
    assert_equal false, updated["emailVerified"]
    assert_includes connection.sql[0], 'SELECT "users"."id" AS "id"'
    assert_includes connection.sql[1], 'UPDATE "users" SET "name" = ?'
    assert_includes connection.sql[2], 'WHERE "users"."id" = ?'
  end

  RecordingConnection = Struct.new(:responses, :sql, :params) do
    def initialize(*responses)
      super(responses, [], [])
    end

    def exec_params(statement, bind_params)
      sql << statement
      params << bind_params
      responses.shift || []
    end
  end
end
