# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthSchemaSQLTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_postgres_ddl_uses_postgres_types_constraints_and_indexes
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n")

    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "users"'
    assert_includes sql, '"id" text PRIMARY KEY'
    assert_includes sql, '"email_verified" boolean NOT NULL DEFAULT false'
    assert_includes sql, '"created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP'
    assert_includes sql, 'UNIQUE ("email")'
    assert_includes sql, 'FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE'
    assert_includes sql, 'CREATE INDEX IF NOT EXISTS "index_sessions_on_user_id" ON "sessions" ("user_id")'
  end

  def test_mysql_ddl_uses_mysql_types_constraints_indexes_and_engine
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :mysql).join("\n")

    assert_includes sql, "CREATE TABLE IF NOT EXISTS `users`"
    assert_includes sql, "`id` varchar(191) PRIMARY KEY"
    assert_includes sql, "`email_verified` tinyint(1) NOT NULL DEFAULT 0"
    assert_includes sql, "`created_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)"
    assert_includes sql, "UNIQUE KEY `uniq_users_email` (`email`)"
    assert_includes sql, "CONSTRAINT `fk_sessions_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE"
    assert_includes sql, "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
  end

  def test_sqlite_ddl_uses_sqlite_types_constraints_and_indexes
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :sqlite).join("\n")

    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "users"'
    assert_includes sql, '"id" text PRIMARY KEY'
    assert_includes sql, '"email_verified" integer NOT NULL DEFAULT 0'
    assert_includes sql, '"created_at" date NOT NULL DEFAULT CURRENT_TIMESTAMP'
    assert_includes sql, 'UNIQUE ("email")'
    assert_includes sql, 'FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE'
    assert_includes sql, 'CREATE INDEX IF NOT EXISTS "index_sessions_on_user_id" ON "sessions" ("user_id")'
  end

  def test_mssql_ddl_uses_mssql_types_constraints_and_indexes
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :mssql).join("\n")

    assert_includes sql, "IF OBJECT_ID(N'[users]', N'U') IS NULL"
    assert_includes sql, "[id] varchar(255) PRIMARY KEY"
    assert_includes sql, "[email_verified] smallint NOT NULL DEFAULT 0"
    assert_includes sql, "[image] varchar(8000) NULL"
    assert_includes sql, "[created_at] datetime2(3) NOT NULL DEFAULT CURRENT_TIMESTAMP"
    assert_includes sql, "CONSTRAINT [uniq_users_email] UNIQUE ([email])"
    assert_includes sql, "CONSTRAINT [fk_sessions_user_id] FOREIGN KEY ([user_id]) REFERENCES [users] ([id]) ON DELETE CASCADE"
    assert_includes sql, "CREATE INDEX [index_sessions_on_user_id] ON [sessions] ([user_id])"
  end

  def test_plugin_sql_schema_includes_organization_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true})
      ]
    )

    sql = BetterAuth::Schema::SQL.create_statements(config, dialect: :postgres).join("\n")

    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "organizations"'
    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "members"'
    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "invitations"'
    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "teams"'
    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "team_members"'
    assert_includes sql, 'CREATE TABLE IF NOT EXISTS "organization_roles"'
    assert_includes sql, '"active_organization_id" text'
    assert_includes sql, '"active_team_id" text'
  end
end
