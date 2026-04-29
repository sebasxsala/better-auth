# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthMongoDBAdapterTest < Minitest::Test
  SECRET = "test-secret-that-is-long-enough-for-validation"

  def setup
    @config = BetterAuth::Configuration.new(secret: SECRET, database: :memory)
    @database = FakeMongoDatabase.new
    @adapter = BetterAuth::Adapters::MongoDB.new(@config, database: @database)
  end

  def test_mongodb_adapter_maps_id_to_bson_id_and_returns_logical_fields
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    stored = @database.collection("user").documents.first

    assert_equal "user-1", user["id"]
    assert_equal "user-1", stored.fetch("_id")
    refute stored.key?("id")
    assert_equal false, user["emailVerified"]
    assert_equal "ada@example.com", @adapter.find_one(model: "user", where: [{field: "id", value: "user-1"}])["email"]
  end

  def test_mongodb_adapter_generates_object_id_documents_by_default
    user = @adapter.create(model: "user", data: {name: "Ada", email: "ada@example.com"})
    stored = @database.collection("user").documents.first

    assert_instance_of BSON::ObjectId, stored.fetch("_id")
    assert_equal stored.fetch("_id").to_s, user.fetch("id")
  end

  def test_mongodb_adapter_supports_where_connectors_sort_limit_offset_and_count
    @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-2", name: "Grace", email: "grace@example.com"}, force_allow_id: true)
    @adapter.create(model: "user", data: {id: "user-3", name: "Linus", email: "linus@example.net"}, force_allow_id: true)

    matches = @adapter.find_many(
      model: "user",
      where: [
        {field: "email", operator: "ends_with", value: "example.net"},
        {field: "name", connector: "OR", value: "Grace"}
      ],
      sort_by: {field: "email", direction: "desc"},
      limit: 2
    )

    assert_equal ["user-3", "user-2"], matches.map { |user| user["id"] }
    assert_equal 2, @adapter.count(model: "user", where: [{field: "email", operator: "ends_with", value: "example.com"}])
  end

  def test_mongodb_adapter_preserves_false_where_values
    verified = @adapter.create(model: "user", data: {id: "user-true", name: "Verified", email: "verified@example.com"}, force_allow_id: true)
    unverified = @adapter.create(model: "user", data: {id: "user-false", name: "Unverified", email: "unverified@example.com"}, force_allow_id: true)
    @adapter.update(model: "user", where: [{field: "id", value: verified.fetch("id")}], update: {emailVerified: true})

    matches = @adapter.find_many(model: "user", where: [{"field" => "emailVerified", "value" => false}])

    assert_equal [unverified.fetch("id")], matches.map { |user| user.fetch("id") }
  end

  def test_mongodb_adapter_supports_core_joins
    user = @adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    session = @adapter.create(model: "session", data: {id: "session-1", token: "token-1", userId: user["id"], expiresAt: Time.now + 60}, force_allow_id: true)
    @adapter.create(model: "account", data: {id: "account-1", userId: user["id"], providerId: "github", accountId: "gh-1"}, force_allow_id: true)

    found_session = @adapter.find_one(model: "session", where: [{field: "token", value: session["token"]}], join: {user: true})
    found_user = @adapter.find_one(model: "user", where: [{field: "id", value: user["id"]}], join: {account: true})

    assert_equal "Ada", found_session["user"]["name"]
    assert_equal ["github"], found_user["account"].map { |account| account["providerId"] }
  end

  def test_mongodb_adapter_persists_auth_routes_and_get_session_reads_database_rows
    require "mongo"

    client = Mongo::Client.new(ENV.fetch("BETTER_AUTH_MONGODB_URL", "mongodb://127.0.0.1:27017/better-auth-ruby-test"), server_selection_timeout: 1)
    client.database.collections.each(&:drop)
    auth = BetterAuth.auth(
      base_url: "http://localhost:3000",
      secret: SECRET,
      database: ->(options) { BetterAuth::Adapters::MongoDB.new(options, database: client.database, client: client, transaction: false) },
      session: {cookie_cache: {enabled: false}}
    )

    status, headers, body = auth.api.sign_up_email(
      body: {email: "mongodb-route@example.com", password: "password123", name: "MongoDB Route"},
      as_response: true
    )
    payload = JSON.parse(body.join)
    token = payload.fetch("token")
    user_id = payload.fetch("user").fetch("id")

    assert_equal 200, status
    assert_equal "mongodb-route@example.com", client.database.collection("user").find(_id: mongo_object_id(user_id)).first.fetch("email")
    assert_equal "credential", client.database.collection("account").find(user_id: mongo_object_id(user_id)).first.fetch("provider_id")
    assert_equal mongo_object_id(user_id), client.database.collection("session").find(token: token).first.fetch("user_id")

    client.database.collection("user").find(_id: mongo_object_id(user_id)).update_one("$set" => {name: "MongoDB Direct Update"})
    session = auth.api.get_session(headers: {"cookie" => cookie_header(headers.fetch("set-cookie"))})

    assert_equal token, session[:session]["token"]
    assert_equal user_id, session[:session]["userId"]
    assert_equal "MongoDB Direct Update", session[:user]["name"]
  rescue LoadError
    skip "mongo gem is not installed"
  rescue Mongo::Error::NoServerAvailable, Mongo::Error::SocketError
    skip "MongoDB test service is not available"
  ensure
    client&.close
  end

  def test_mongodb_adapter_wraps_operations_in_client_transaction_when_enabled
    database = FakeMongoDatabase.new
    client = FakeMongoClient.new
    adapter = BetterAuth::Adapters::MongoDB.new(@config, database: database, client: client)

    adapter.transaction do |transaction_adapter|
      transaction_adapter.create(model: "user", data: {id: "user-1", name: "Ada", email: "ada@example.com"}, force_allow_id: true)
    end

    assert_equal 1, client.sessions.length
    session = client.sessions.first
    assert_equal true, session.started
    assert_equal true, session.committed
    assert_equal false, session.aborted
    assert_equal true, session.ended
    assert_equal session, database.collection("user").insert_options.first.fetch(:session)
  end

  private

  def mongo_object_id(value)
    BSON::ObjectId.from_string(value)
  rescue BSON::ObjectId::Invalid
    value
  end

  def cookie_header(set_cookie)
    set_cookie.lines.map { |line| line.split(";").first }.join("; ")
  end

  class FakeMongoDatabase
    def initialize
      @collections = {}
    end

    def collection(name)
      @collections[name.to_s] ||= FakeMongoCollection.new
    end
  end

  class FakeMongoCollection
    attr_reader :documents
    attr_reader :insert_options

    def initialize
      @documents = []
      @insert_options = []
    end

    def insert_one(document, options = {})
      @insert_options << options
      @documents << deep_dup(document)
      InsertResult.new(document.fetch("_id"))
    end

    def all_documents
      @documents.map { |document| deep_dup(document) }
    end

    def replace_documents(documents)
      @documents = documents.map { |document| deep_dup(document) }
    end

    InsertResult = Struct.new(:inserted_id)

    private

    def deep_dup(value)
      Marshal.load(Marshal.dump(value))
    end
  end

  class FakeMongoClient
    attr_reader :sessions

    def initialize
      @sessions = []
    end

    def start_session
      FakeMongoSession.new.tap { |session| sessions << session }
    end
  end

  class FakeMongoSession
    attr_reader :started, :committed, :aborted, :ended

    def initialize
      @started = false
      @committed = false
      @aborted = false
      @ended = false
    end

    def start_transaction
      @started = true
    end

    def commit_transaction
      @committed = true
    end

    def abort_transaction
      @aborted = true
    end

    def end_session
      @ended = true
    end
  end
end
