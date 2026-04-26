# frozen_string_literal: true

require "json"
require "securerandom"
require "time"

module BetterAuth
  module Adapters
    class InternalAdapter
      attr_reader :adapter, :options, :hooks

      def initialize(adapter, options)
        @adapter = adapter
        @options = options
        @hooks = DatabaseHooks.new(adapter, options)
      end

      def create_oauth_user(user, account)
        adapter.transaction do
          created_user = create_user(user)
          created_account = create_account(stringify_keys(account).merge("userId" => created_user["id"]))
          {user: created_user, account: created_account}
        end
      end

      def create_user(user)
        data = timestamps.merge(stringify_keys(user))
        data["email"] = data["email"].to_s.downcase if data["email"]
        hooks.create(data, "user")
      end

      def create_account(account)
        hooks.create(timestamps.merge(stringify_keys(account)), "account")
      end

      def link_account(account)
        create_account(account)
      end

      def list_sessions(user_id)
        if secondary_storage
          active_session_entries(user_id).filter_map do |entry|
            data = parse_storage(secondary_storage.get(entry.fetch("token")))
            next unless data && data["session"]

            normalize_session_dates(data["session"])
          end
        else
          adapter.find_many(model: "session", where: [{field: "userId", value: user_id}])
        end
      end

      def list_users(limit: nil, offset: nil, sort_by: nil, where: nil)
        adapter.find_many(model: "user", where: where || [], limit: limit, offset: offset, sort_by: sort_by)
      end

      def count_total_users(where: nil)
        adapter.count(model: "user", where: where || [])
      end

      def delete_user(user_id)
        delete_sessions(user_id) if !secondary_storage || options.session[:store_session_in_database]
        hooks.delete_many([{field: "userId", value: user_id}], "account")
        hooks.delete([{field: "id", value: user_id}], "user")
      end

      def create_session(user_id, dont_remember_me = false, override = nil, override_all = false, context = nil)
        override = stringify_keys(override || {})
        token = override.delete("token") || SecureRandom.hex(16)
        base = {
          "ipAddress" => "",
          "userAgent" => "",
          "expiresAt" => Time.now + (dont_remember_me ? 86_400 : options.session[:expires_in].to_i),
          "userId" => user_id,
          "token" => token
        }.merge(timestamps)
        data = override_all ? base.merge(override) : override.merge(base)

        custom = secondary_storage && lambda do |session_data|
          store_session(session_data)
          session_data
        end
        execute_main = !secondary_storage || options.session[:store_session_in_database]
        created = hooks.create(data, "session", custom: custom, context: context)
        adapter.create(model: "session", data: data, force_allow_id: true) if secondary_storage && execute_main
        created
      end

      def find_session(token)
        if secondary_storage
          data = parse_storage(secondary_storage.get(token))
          return nil unless data

          return {
            session: normalize_session_dates(data["session"]),
            user: normalize_user_dates(data["user"])
          }
        end

        found = adapter.find_one(model: "session", where: [{field: "token", value: token}], join: {user: true})
        return nil unless found && found["user"]

        user = found.delete("user")
        {session: found, user: user}
      end

      def find_sessions(tokens)
        tokens.filter_map { |token| find_session(token) }
      end

      def update_session(token, session)
        data = stringify_keys(session)
        if secondary_storage
          return hooks.update(data, [{field: "token", value: token}], "session", custom: lambda { |actual_data|
            update_stored_session(token, actual_data)
          })
        end

        hooks.update(data, [{field: "token", value: token}], "session")
      end

      def delete_session(token)
        if secondary_storage
          data = parse_storage(secondary_storage.get(token))
          if data && data["session"]
            user_id = data["session"]["userId"]
            entries = active_session_entries(user_id).reject { |entry| entry["token"] == token }
            write_active_sessions(user_id, entries)
          end
          secondary_storage.delete(token)
          return if !options.session[:store_session_in_database] || options.session[:preserve_session_in_database]
        end

        hooks.delete([{field: "token", value: token}], "session")
      end

      def delete_sessions(user_id_or_tokens)
        if secondary_storage
          if user_id_or_tokens.is_a?(Array)
            user_id_or_tokens.each { |token| secondary_storage.delete(token) }
          else
            active_session_entries(user_id_or_tokens).each { |entry| secondary_storage.delete(entry["token"]) }
            secondary_storage.delete(active_key(user_id_or_tokens))
          end
          return if !options.session[:store_session_in_database] || options.session[:preserve_session_in_database]
        end

        field = user_id_or_tokens.is_a?(Array) ? "token" : "userId"
        operator = user_id_or_tokens.is_a?(Array) ? "in" : nil
        hooks.delete_many([{field: field, value: user_id_or_tokens, operator: operator}], "session")
      end

      def delete_accounts(user_id)
        hooks.delete_many([{field: "userId", value: user_id}], "account")
      end

      def delete_account(account_id)
        hooks.delete([{field: "id", value: account_id}], "account")
      end

      def find_oauth_user(email, account_id, provider_id)
        account = adapter.find_one(model: "account", where: [{field: "accountId", value: account_id}, {field: "providerId", value: provider_id}], join: {user: true})
        if account
          user = account["user"] || adapter.find_one(model: "user", where: [{field: "email", value: email.to_s.downcase}])
          return nil unless user

          linked = account.dup
          linked.delete("user")
          return {user: user, linked_account: linked, accounts: [linked]}
        end

        found_user = adapter.find_one(model: "user", where: [{field: "email", value: email.to_s.downcase}])
        return nil unless found_user

        {user: found_user, linked_account: nil, accounts: find_accounts(found_user["id"])}
      end

      def find_user_by_email(email, include_accounts: false)
        user = adapter.find_one(model: "user", where: [{field: "email", value: email.to_s.downcase}])
        return nil unless user

        {user: user, accounts: include_accounts ? find_accounts(user["id"]) : []}
      end

      def find_user_by_id(user_id)
        return nil if user_id.to_s.empty?

        adapter.find_one(model: "user", where: [{field: "id", value: user_id}])
      end

      def update_user(user_id, data)
        user = hooks.update(stringify_keys(data), [{field: "id", value: user_id}], "user")
        refresh_user_sessions(user) if user
        user
      end

      def update_user_by_email(email, data)
        user = hooks.update(stringify_keys(data), [{field: "email", value: email.to_s.downcase}], "user")
        refresh_user_sessions(user) if user
        user
      end

      def update_password(user_id, password)
        hooks.update_many({password: password}, [{field: "userId", value: user_id}, {field: "providerId", value: "credential"}], "account")
      end

      def find_accounts(user_id)
        adapter.find_many(model: "account", where: [{field: "userId", value: user_id}])
      end

      def find_account(account_id)
        adapter.find_one(model: "account", where: [{field: "accountId", value: account_id}])
      end

      def find_account_by_provider_id(account_id, provider_id)
        adapter.find_one(model: "account", where: [{field: "accountId", value: account_id}, {field: "providerId", value: provider_id}])
      end

      def find_account_by_user_id(user_id)
        find_accounts(user_id)
      end

      def update_account(id, data)
        hooks.update(stringify_keys(data), [{field: "id", value: id}], "account")
      end

      def create_verification_value(data)
        hooks.create(timestamps.merge(stringify_keys(data)), "verification")
      end

      def find_verification_value(identifier)
        values = adapter.find_many(
          model: "verification",
          where: [{field: "identifier", value: identifier}],
          sort_by: {field: "createdAt", direction: "desc"},
          limit: 1
        )
        hooks.delete_many([{field: "expiresAt", value: Time.now, operator: "lt"}], "verification") unless options.verification[:disable_cleanup]
        values.first
      end

      def delete_verification_value(id)
        hooks.delete([{field: "id", value: id}], "verification")
      end

      def delete_verification_by_identifier(identifier)
        hooks.delete([{field: "identifier", value: identifier}], "verification")
      end

      def update_verification_value(id, data)
        hooks.update(stringify_keys(data), [{field: "id", value: id}], "verification")
      end

      private

      def secondary_storage
        options.secondary_storage
      end

      def timestamps
        now = Time.now
        {"createdAt" => now, "updatedAt" => now}
      end

      def stringify_keys(data)
        data.each_with_object({}) do |(key, value), result|
          result[Schema.storage_key(key)] = value
        end
      end

      def store_session(session)
        user = adapter.find_one(model: "user", where: [{field: "id", value: session["userId"]}])
        now_ms = current_millis
        expires_ms = millis(session["expiresAt"])
        entries = active_session_entries(session["userId"])
          .reject { |entry| entry["expiresAt"].to_i <= now_ms || entry["token"] == session["token"] }
          .push({"token" => session["token"], "expiresAt" => expires_ms})
          .sort_by { |entry| entry["expiresAt"] }
        write_active_sessions(session["userId"], entries)
        secondary_storage.set(session["token"], JSON.generate({session: session, user: user}), ttl(expires_ms))
      end

      def update_stored_session(token, data)
        parsed = parse_storage(secondary_storage.get(token))
        return nil unless parsed && parsed["session"]

        merged = parsed["session"].merge(data)
        merged["expiresAt"] = normalize_time(merged["expiresAt"])
        merged["createdAt"] = normalize_time(merged["createdAt"])
        merged["updatedAt"] = normalize_time(merged["updatedAt"])
        secondary_storage.set(token, JSON.generate({session: merged, user: parsed["user"]}), ttl(millis(merged["expiresAt"])))
        entries = active_session_entries(merged["userId"])
          .reject { |entry| entry["token"] == token || entry["expiresAt"].to_i <= current_millis }
          .push({"token" => token, "expiresAt" => millis(merged["expiresAt"])})
          .sort_by { |entry| entry["expiresAt"] }
        write_active_sessions(merged["userId"], entries)
        merged
      end

      def refresh_user_sessions(user)
        return unless secondary_storage && user

        active_session_entries(user["id"]).each do |entry|
          parsed = parse_storage(secondary_storage.get(entry["token"]))
          next unless parsed && parsed["session"]

          secondary_storage.set(entry["token"], JSON.generate({session: parsed["session"], user: user}), ttl(millis(parsed["session"]["expiresAt"])))
        end
      end

      def active_session_entries(user_id)
        raw = secondary_storage.get(active_key(user_id))
        Array(parse_storage(raw)).map do |entry|
          entry.transform_keys(&:to_s)
        end
      end

      def write_active_sessions(user_id, entries)
        future = entries.select { |entry| entry["expiresAt"].to_i > current_millis }.sort_by { |entry| entry["expiresAt"] }
        if future.empty?
          secondary_storage.delete(active_key(user_id))
        else
          secondary_storage.set(active_key(user_id), JSON.generate(future), ttl(future.last["expiresAt"]))
        end
      end

      def active_key(user_id)
        "active-sessions-#{user_id}"
      end

      def parse_storage(value)
        return value.transform_keys(&:to_s) if value.is_a?(Hash)
        return value.map { |entry| entry.is_a?(Hash) ? entry.transform_keys(&:to_s) : entry } if value.is_a?(Array)
        return nil unless value

        parsed = JSON.parse(value)
        parse_storage(parsed)
      rescue JSON::ParserError
        nil
      end

      def normalize_session_dates(session)
        return nil unless session

        session.transform_keys(&:to_s).merge(
          "expiresAt" => normalize_time(session["expiresAt"] || session[:expiresAt]),
          "createdAt" => normalize_time(session["createdAt"] || session[:createdAt]),
          "updatedAt" => normalize_time(session["updatedAt"] || session[:updatedAt])
        )
      end

      def normalize_user_dates(user)
        return nil unless user

        user.transform_keys(&:to_s).merge(
          "createdAt" => normalize_time(user["createdAt"] || user[:createdAt]),
          "updatedAt" => normalize_time(user["updatedAt"] || user[:updatedAt])
        )
      end

      def normalize_time(value)
        return value if value.is_a?(Time)
        return Time.at(value / 1000.0) if value.is_a?(Integer) && value > 10_000_000_000
        return Time.at(value) if value.is_a?(Integer)

        Time.parse(value.to_s)
      end

      def millis(value)
        (normalize_time(value).to_f * 1000).to_i
      end

      def ttl(expires_ms)
        [(expires_ms - current_millis) / 1000, 0].max.floor
      end

      def current_millis
        (Time.now.to_f * 1000).to_i
      end
    end
  end
end
