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
