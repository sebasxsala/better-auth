# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthSchemaTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def test_core_tables_preserve_logical_names_and_default_to_postgres_snake_case_storage_names
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal %w[user session account verification], schema.keys
    assert_equal "users", schema["user"][:model_name]
    assert_equal "sessions", schema["session"][:model_name]
    assert_equal "accounts", schema["account"][:model_name]
    assert_equal "verifications", schema["verification"][:model_name]

    assert_equal %w[id name email emailVerified image createdAt updatedAt], schema["user"][:fields].keys
    assert_equal "boolean", schema["user"][:fields]["emailVerified"][:type]
    assert_equal false, schema["user"][:fields]["emailVerified"][:input]
    assert_equal true, schema["user"][:fields]["email"][:unique]
    assert_equal true, schema["session"][:fields]["token"][:unique]
    assert_equal true, schema["session"][:fields]["userId"][:index]
    assert_equal "users", schema["session"][:fields]["userId"][:references][:model]
    assert_equal "email_verified", schema["user"][:fields]["emailVerified"][:field_name]
    assert_equal "created_at", schema["user"][:fields]["createdAt"][:field_name]
    assert_equal "updated_at", schema["user"][:fields]["updatedAt"][:field_name]
    assert_equal "user_id", schema["session"][:fields]["userId"][:field_name]
    assert_equal "ip_address", schema["session"][:fields]["ipAddress"][:field_name]
    assert_equal "user_agent", schema["session"][:fields]["userAgent"][:field_name]
    assert_equal "access_token", schema["account"][:fields]["accessToken"][:field_name]
    assert_equal "refresh_token_expires_at", schema["account"][:fields]["refreshTokenExpiresAt"][:field_name]
    assert_equal "last_request", BetterAuth::Schema.auth_tables(
      BetterAuth::Configuration.new(secret: SECRET, database: :memory, rate_limit: {storage: "database"})
    ).fetch("rateLimit").fetch(:fields).fetch("lastRequest").fetch(:field_name)
    assert_equal "rate_limits", BetterAuth::Schema.auth_tables(
      BetterAuth::Configuration.new(secret: SECRET, database: :memory, rate_limit: {storage: "database"})
    ).fetch("rateLimit").fetch(:model_name)
  end

  def test_custom_field_mappings_and_additional_fields_merge_into_core_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      user: {
        fields: {
          email: "email_address",
          emailVerified: "email_verified"
        },
        additional_fields: {
          "role" => {type: "string", default_value: "member"}
        }
      },
      session: {
        fields: {
          userId: "user_id"
        }
      }
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "email_address", schema["user"][:fields]["email"][:field_name]
    assert_equal "email_verified", schema["user"][:fields]["emailVerified"][:field_name]
    assert_equal "member", schema["user"][:fields]["role"][:default_value]
    assert_equal "user_id", schema["session"][:fields]["userId"][:field_name]
  end

  def test_plugin_schema_merges_fields_and_tables
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "organization",
          schema: {
            session: {
              fields: {
                activeOrganizationId: {type: "string", required: false}
              }
            },
            organization: {
              model_name: "organization",
              fields: {
                name: {type: "string", required: true}
              }
            }
          }
        }
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "string", schema["session"][:fields]["activeOrganizationId"][:type]
    assert_equal "active_organization_id", schema["session"][:fields]["activeOrganizationId"][:field_name]
    assert_equal "organization", schema["organization"][:model_name]
    assert_equal "string", schema["organization"][:fields]["name"][:type]
  end

  def test_plugin_schema_defaults_physical_table_names_to_snake_case
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      plugins: [
        {
          id: "api-key",
          schema: {
            apiKey: {
              fields: {
                userId: {type: "string", required: true},
                lastRequest: {type: "date", required: false}
              }
            }
          }
        }
      ]
    )

    schema = BetterAuth::Schema.auth_tables(config)

    assert_equal "api_key", schema["apiKey"][:model_name]
    assert_equal "user_id", schema["apiKey"][:fields]["userId"][:field_name]
    assert_equal "last_request", schema["apiKey"][:fields]["lastRequest"][:field_name]
  end

  def test_secondary_storage_omits_session_table_unless_database_storage_enabled
    storage = Object.new
    config = BetterAuth::Configuration.new(secret: SECRET, database: :memory, secondary_storage: storage)

    refute_includes BetterAuth::Schema.auth_tables(config).keys, "session"

    with_db_sessions = BetterAuth::Configuration.new(
      secret: SECRET,
      database: :memory,
      secondary_storage: storage,
      session: {store_session_in_database: true}
    )

    assert_includes BetterAuth::Schema.auth_tables(with_db_sessions).keys, "session"
  end
end
