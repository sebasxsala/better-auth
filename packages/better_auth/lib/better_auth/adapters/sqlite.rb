# frozen_string_literal: true

module BetterAuth
  module Adapters
    class SQLite < SQL
      attr_reader :path

      def initialize(options = nil, path: nil, connection: nil)
        require "sqlite3" unless connection

        config = options || Configuration.new(secret: Configuration::DEFAULT_SECRET, database: :memory)
        @path = path || ":memory:"
        connection ||= SQLite3::Database.new(@path)
        connection.results_as_hash = true if connection.respond_to?(:results_as_hash=)
        connection.execute("PRAGMA foreign_keys = ON") if connection.respond_to?(:execute)
        super(config, connection: connection, dialect: :sqlite)
      end
    end
  end
end
