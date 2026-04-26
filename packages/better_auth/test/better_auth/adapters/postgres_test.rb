# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthPostgresAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_postgres_adapter_can_be_instantiated_without_rails
    adapter = BetterAuth::Adapters::Postgres.new(url: "postgres://user:password@localhost:5432/better_auth")

    assert_equal :postgres, adapter.dialect
  rescue LoadError
    skip "pg gem is not installed"
  end

  def test_postgres_adapter_runs_core_crud_against_docker_service
    require "pg"

    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    connection = PG.connect(ENV.fetch("BETTER_AUTH_POSTGRES_URL", "postgres://user:password@localhost:5432/better_auth"))
    reset_schema(connection)
    BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).each { |statement| connection.exec(statement) }
    adapter = BetterAuth::Adapters::Postgres.new(config, connection: connection)

    user = adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    found = adapter.find_one(model: "user", where: [{field: "email", value: "ada@example.com"}])

    assert_equal "user-1", user["id"]
    assert_equal false, user["emailVerified"]
    assert_equal "Ada", found["name"]
  rescue LoadError
    skip "pg gem is not installed"
  rescue PG::ConnectionBad
    skip "PostgreSQL test service is not available"
  ensure
    connection&.close
  end

  private

  def reset_schema(connection)
    %w[rate_limits verifications accounts sessions users].each do |table|
      connection.exec(%(DROP TABLE IF EXISTS "#{table}" CASCADE))
    end
  end
end
