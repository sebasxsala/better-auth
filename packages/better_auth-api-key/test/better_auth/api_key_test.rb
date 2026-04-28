# frozen_string_literal: true

require_relative "../test_helper"

class BetterAuthPluginsAPIKeyTest < Minitest::Test
  SECRET = "phase-nine-api-key-secret-with-enough-entropy"

  def test_create_verify_get_list_update_and_delete_api_key
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "api-key@example.com")

    created = auth.api.create_api_key(
      headers: {"cookie" => cookie},
      body: {name: "primary", prefix: "ba_", metadata: {plan: "pro"}, permissions: {repo: ["read"]}}
    )

    assert_match(/\Aba_[A-Za-z]+\z/, created[:key])
    assert_equal "ba_", created[:prefix]
    assert_equal "primary", created[:name]
    assert_equal({"plan" => "pro"}, created[:metadata])

    verified = auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})
    assert_equal true, verified[:valid]
    assert_equal created[:id], verified[:key][:id]
    assert_nil verified[:error]
    refute verified[:key].key?("key")

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal "primary", fetched[:name]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie})
    assert_equal [created[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] || entry["id"] }
    assert_equal 1, listed.fetch(:total)

    updated = auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], name: "renamed", enabled: false})
    assert_equal "renamed", updated[:name]
    assert_equal false, updated[:enabled]

    disabled = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal false, disabled[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_DISABLED"], disabled[:error][:message]
    assert_nil disabled[:key]

    assert_equal({success: true}, auth.api.delete_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id]}))
    assert_raises(BetterAuth::APIError) { auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]}) }
  end

  def test_expiration_remaining_refill_and_rate_limit
    auth = build_auth(rate_limit: {enabled: true, time_window: 60_000, max_requests: 1})
    cookie = sign_up_cookie(auth, email: "limits@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"], assert_raises(BetterAuth::APIError) {
      auth.api.create_api_key(body: {userId: user_id, expiresIn: 60 * 60 * 12})
    }.message

    expired = auth.api.create_api_key(body: {userId: user_id})
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: expired[:id]}], update: {expiresAt: Time.now - 10})
    expired_result = auth.api.verify_api_key(body: {key: expired[:key]})
    assert_equal false, expired_result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_EXPIRED"], expired_result[:error][:message]

    limited = auth.api.create_api_key(body: {userId: user_id, remaining: 1})
    assert_equal true, auth.api.verify_api_key(body: {key: limited[:key]})[:valid]
    usage_exceeded = auth.api.verify_api_key(body: {key: limited[:key]})
    assert_equal false, usage_exceeded[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["USAGE_EXCEEDED"], usage_exceeded[:error][:message]

    rate_limited = auth.api.create_api_key(body: {userId: user_id, rateLimitEnabled: true, rateLimitMax: 1, rateLimitTimeWindow: 60_000})
    assert_equal true, auth.api.verify_api_key(body: {key: rate_limited[:key]})[:valid]
    rate_error = auth.api.verify_api_key(body: {key: rate_limited[:key]})
    assert_equal false, rate_error[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"], rate_error[:error][:message]

    refill = auth.api.create_api_key(body: {userId: user_id, remaining: 0, refillAmount: 2, refillInterval: 1})
    stored = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: refill[:id]}])
    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: stored["id"]}], update: {lastRequest: Time.now - 10, lastRefillAt: Time.now - 10})
    assert_equal true, auth.api.verify_api_key(body: {key: refill[:key]})[:valid]
  end

  def test_secondary_storage_and_api_key_session
    storage = MemoryStorage.new
    auth = build_auth(
      storage: "secondary-storage",
      secondary_storage: storage,
      fallback_to_database: true,
      enable_session_for_api_keys: true,
      session: {store_session_in_database: true}
    )
    cookie = sign_up_cookie(auth, email: "storage-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "storage"})

    assert storage.keys.any? { |key| key.include?(created[:id]) }
    session = auth.api.get_session(headers: {"x-api-key" => created[:key]})

    assert_equal "storage-key@example.com", session[:user]["email"]
    assert_equal created[:id], session[:session]["id"]
  end

  def test_validation_errors_match_upstream
    auth = build_auth(require_name: true)
    cookie = sign_up_cookie(auth, email: "validation-key@example.com")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["NAME_REQUIRED"], error.message

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(headers: {"cookie" => cookie}, body: {name: "bad", userId: "someone-else"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], client_server_only.message
  end

  def test_multiple_configurations_default_prefix_and_config_filters
    auth = build_auth([
      {config_id: "public-api", default_prefix: "pub_", default_key_length: 12},
      {config_id: "internal-api", default_prefix: "int_", default_key_length: 12},
      {config_id: "default", default_prefix: "def_", default_key_length: 12}
    ])
    cookie = sign_up_cookie(auth, email: "multi-config-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    public_key = auth.api.create_api_key(body: {configId: "public-api", userId: user_id})
    internal_key = auth.api.create_api_key(body: {configId: "internal-api", userId: user_id})
    default_key = auth.api.create_api_key(body: {userId: user_id})

    assert_equal "public-api", public_key[:configId]
    assert_equal "pub_", public_key[:prefix]
    assert_match(/\Apub_[A-Za-z]+\z/, public_key[:key])
    assert_equal user_id, public_key[:referenceId]
    assert_equal "internal-api", internal_key[:configId]
    assert_equal "int_", internal_key[:prefix]
    assert_equal "default", default_key[:configId]
    assert_equal "def_", default_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {configId: "public-api"})
    assert_equal [public_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }
    assert_equal 1, listed.fetch(:total)

    verified = auth.api.verify_api_key(body: {configId: "internal-api", key: internal_key[:key]})
    assert_equal true, verified[:valid]
    assert_equal "internal-api", verified[:key][:configId]
  end

  def test_multiple_configuration_validation
    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "duplicate"}, {config_id: "duplicate"}])
    end

    assert_raises(BetterAuth::Error) do
      BetterAuth::Plugins.api_key([{config_id: "valid"}, {}])
    end
  end

  def test_list_paginates_sorts_and_returns_upstream_shape
    auth = build_auth(default_key_length: 12)
    cookie = sign_up_cookie(auth, email: "list-shape-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.api.create_api_key(body: {userId: user_id, name: "zulu"})
    auth.api.create_api_key(body: {userId: user_id, name: "alpha"})
    auth.api.create_api_key(body: {userId: user_id, name: "mike"})

    listed = auth.api.list_api_keys(headers: {"cookie" => cookie}, query: {limit: 2, offset: 1, sortBy: "name", sortDirection: "asc"})

    assert_equal %w[mike zulu], listed.fetch(:apiKeys).map { |entry| entry[:name] }
    assert_equal 3, listed.fetch(:total)
    assert_equal 2, listed.fetch(:limit)
    assert_equal 1, listed.fetch(:offset)
  end

  def test_verify_invalid_key_returns_error_payload
    auth = build_auth(default_key_length: 12)

    result = auth.api.verify_api_key(body: {key: "missing-key"})

    assert_equal false, result[:valid]
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_API_KEY"], result[:error][:message]
    assert_equal "INVALID_API_KEY", result[:error][:code]
    assert_nil result[:key]
  end

  def test_default_permissions_callable_and_prefix_validation
    calls = []
    auth = build_auth(
      default_key_length: 12,
      permissions: {
        default_permissions: ->(reference_id, ctx) {
          calls << [reference_id, ctx.path]
          {repo: ["read"]}
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "permissions-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]

    invalid_prefix = assert_raises(BetterAuth::APIError) do
      auth.api.create_api_key(body: {userId: user_id, prefix: "bad prefix"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"], invalid_prefix.message

    created = auth.api.create_api_key(body: {userId: user_id})
    assert_equal({"repo" => ["read"]}, created[:permissions])
    assert_equal [[user_id, "/api-key/create"]], calls
    assert_equal true, auth.api.verify_api_key(body: {key: created[:key], permissions: {repo: ["read"]}})[:valid]
  end

  def test_organization_owned_api_keys_require_membership_permissions_and_filtering
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      apiKey: ["create", "read", "update", "delete"]
    )
    auth = BetterAuth.auth(
      secret: SECRET,
      email_and_password: {enabled: true},
      plugins: [
        BetterAuth::Plugins.organization(
          ac: ac,
          roles: {
            owner: ac.new_role(member: ["create", "update", "delete"], apiKey: ["create", "read", "update", "delete"]),
            member: ac.new_role(apiKey: ["read"])
          }
        ),
        BetterAuth::Plugins.api_key([
          {config_id: "user-keys", default_prefix: "usr_", references: "user", default_key_length: 12},
          {config_id: "org-keys", default_prefix: "org_", references: "organization", default_key_length: 12}
        ])
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "org-owner-key@example.com")
    member_cookie = sign_up_cookie(auth, email: "org-member-key@example.com")
    member_id = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]["id"]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "API Org", slug: "api-org"})
    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_id, role: "member"})

    org_key = auth.api.create_api_key(headers: {"cookie" => owner_cookie}, body: {configId: "org-keys", organizationId: organization.fetch("id")})

    assert_equal "org-keys", org_key[:configId]
    assert_equal organization.fetch("id"), org_key[:referenceId]
    assert_equal "org_", org_key[:prefix]

    listed = auth.api.list_api_keys(headers: {"cookie" => member_cookie}, query: {organizationId: organization.fetch("id")})
    assert_equal [org_key[:id]], listed.fetch(:apiKeys).map { |entry| entry[:id] }

    insufficient = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => member_cookie}, body: {configId: "org-keys", keyId: org_key[:id], name: "blocked"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["INSUFFICIENT_API_KEY_PERMISSIONS"], insufficient.message
  end

  def test_update_auth_boundaries_match_upstream
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "owner-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, permissions: {repo: ["read"]}})

    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"], unauthorized.message

    missing = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(body: {keyId: created[:id], userId: "different-user", name: "stolen"})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["KEY_NOT_FOUND"], missing.message

    server_update = auth.api.update_api_key(body: {keyId: created[:id], userId: user_id, permissions: {repo: ["read", "write"]}})
    assert_equal({"repo" => ["read", "write"]}, server_update[:permissions])

    client_server_only = assert_raises(BetterAuth::APIError) do
      auth.api.update_api_key(headers: {"cookie" => cookie}, body: {keyId: created[:id], permissions: {repo: ["admin"]}})
    end
    assert_equal BetterAuth::Plugins::API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"], client_server_only.message
  end

  def test_legacy_double_stringified_metadata_is_returned_as_object_and_migrated
    auth = build_auth(enable_metadata: true)
    cookie = sign_up_cookie(auth, email: "metadata-key@example.com")
    created = auth.api.create_api_key(headers: {"cookie" => cookie}, body: {metadata: {tier: "free"}})
    legacy = JSON.generate(JSON.generate({tier: "legacy"}))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})

    fetched = auth.api.get_api_key(headers: {"cookie" => cookie}, query: {id: created[:id]})
    assert_equal({"tier" => "legacy"}, fetched[:metadata])

    migrated = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_equal({"tier" => "legacy"}, JSON.parse(migrated["metadata"]))

    auth.context.adapter.update(model: "apikey", where: [{field: "id", value: created[:id]}], update: {metadata: legacy})
    verified = auth.api.verify_api_key(body: {key: created[:key]})
    assert_equal({"tier" => "legacy"}, verified[:key][:metadata])
  end

  def test_defer_updates_uses_configured_background_task_handler
    deferred = []
    auth = build_auth(
      defer_updates: true,
      advanced: {
        background_tasks: {
          handler: ->(task) { deferred << task }
        }
      }
    )
    cookie = sign_up_cookie(auth, email: "defer-key@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    created = auth.api.create_api_key(body: {userId: user_id, remaining: 2})

    result = auth.api.verify_api_key(body: {key: created[:key]})

    assert_equal true, result[:valid]
    assert_equal 1, result[:key][:remaining]
    assert_equal 1, deferred.length
    stored_before_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert_nil stored_before_task["lastRequest"]
    deferred.each(&:call)
    stored_after_task = auth.context.adapter.find_one(model: "apikey", where: [{field: "id", value: created[:id]}])
    assert stored_after_task["lastRequest"]
    assert_equal 1, stored_after_task["remaining"]
  end

  def build_auth(options = {})
    advanced = options.is_a?(Hash) ? options.delete(:advanced) : nil
    secondary_storage = options.is_a?(Hash) ? options.delete(:secondary_storage) : nil
    session = options.is_a?(Hash) ? options.delete(:session) : nil
    BetterAuth.auth({
      secret: SECRET,
      email_and_password: {enabled: true},
      advanced: advanced,
      secondary_storage: secondary_storage,
      session: session,
      plugins: [BetterAuth::Plugins.api_key(options)]
    }.compact)
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "API Key"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end

  class MemoryStorage
    attr_reader :values

    def initialize
      @values = {}
    end

    def get(key)
      values[key]
    end

    def set(key, value, _ttl = nil)
      values[key] = value
    end

    def delete(key)
      values.delete(key)
    end

    def keys
      values.keys
    end
  end
end
