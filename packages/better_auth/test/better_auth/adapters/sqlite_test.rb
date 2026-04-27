# frozen_string_literal: true

require "json"
require "tempfile"
require_relative "../../test_helper"

class BetterAuthSQLiteAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_sqlite_adapter_can_be_instantiated_with_injected_connection
    connection = Object.new
    adapter = BetterAuth::Adapters::SQLite.new(connection: connection)

    assert_equal :sqlite, adapter.dialect
    assert_same connection, adapter.connection
  end

  def test_sqlite_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "sqlite3"

    Tempfile.create(["better-auth", ".sqlite3"]) do |file|
      config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
      connection = SQLite3::Database.new(file.path)
      connection.results_as_hash = true
      connection.execute("PRAGMA foreign_keys = ON")
      create_schema(connection, config)

      auth = BetterAuth.auth(
        base_url: "http://localhost:3000",
        secret: SECRET,
        database: ->(options) { BetterAuth::Adapters::SQLite.new(options, connection: connection) },
        session: {cookie_cache: {enabled: false}}
      )

      status, headers, body = auth.api.sign_up_email(
        body: {email: "sqlite-route@example.com", password: "password123", name: "SQLite Route"},
        as_response: true
      )
      payload = JSON.parse(body.join)
      token = payload.fetch("token")
      user_id = payload.fetch("user").fetch("id")

      assert_equal 200, status
      assert_equal "sqlite-route@example.com", direct_sqlite_value(connection, %(SELECT email FROM "users" WHERE id = ?), user_id)
      assert_equal "credential", direct_sqlite_value(connection, %(SELECT provider_id FROM "accounts" WHERE user_id = ?), user_id)
      assert_equal user_id, direct_sqlite_value(connection, %(SELECT user_id FROM "sessions" WHERE token = ?), token)

      connection.execute(%(UPDATE "users" SET "name" = ? WHERE id = ?), ["SQLite Direct Update", user_id])
      session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

      assert_equal token, session[:session]["token"]
      assert_equal user_id, session[:session]["userId"]
      assert_equal "SQLite Direct Update", session[:user]["name"]
    ensure
      connection&.close
    end
  rescue LoadError
    skip "sqlite3 gem is not installed"
  end

  private

  def create_schema(connection, config)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :sqlite).each { |statement| connection.execute(statement) }
  end

  def direct_sqlite_value(connection, sql, *params)
    connection.execute(sql, params).first&.values&.first
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end
end
