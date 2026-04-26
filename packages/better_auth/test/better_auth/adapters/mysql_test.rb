# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthMySQLAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_mysql_adapter_can_be_instantiated_without_rails
    adapter = BetterAuth::Adapters::MySQL.new(url: "mysql2://user:password@127.0.0.1:3306/better_auth")

    assert_equal :mysql, adapter.dialect
  rescue LoadError
    skip "mysql2 gem is not installed"
  end

  def test_mysql_adapter_runs_core_crud_against_docker_service
    require "mysql2"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = Mysql2::Client.new(
      host: ENV.fetch("BETTER_AUTH_MYSQL_HOST", "127.0.0.1"),
      port: ENV.fetch("BETTER_AUTH_MYSQL_PORT", "3306").to_i,
      username: ENV.fetch("BETTER_AUTH_MYSQL_USER", "user"),
      password: ENV.fetch("BETTER_AUTH_MYSQL_PASSWORD", "password"),
      database: ENV.fetch("BETTER_AUTH_MYSQL_DATABASE", "better_auth"),
      symbolize_keys: false
    )
    reset_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).each { |statement| connection.query(statement) }
    adapter = BetterAuth::Adapters::MySQL.new(config, connection: connection)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    found = adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])

    assert_equal "user-1", user["id"]
    assert_equal false, user["emailVerified"]
    assert_equal "Ada", found["name"]
  rescue LoadError
    skip "mysql2 gem is not installed"
  rescue Mysql2::Error::ConnectionError
    skip "MySQL test service is not available"
  ensure
    connection&.close
  end

  private

  def reset_schema(connection)
    connection.query("SET FOREIGN_KEY_CHECKS = 0")
    %w[rate_limits verifications accounts sessions users].each do |table|
      connection.query("DROP TABLE IF EXISTS `#{table}`")
    end
    connection.query("SET FOREIGN_KEY_CHECKS = 1")
  end
end
