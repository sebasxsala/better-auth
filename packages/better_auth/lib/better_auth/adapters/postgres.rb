# frozen_string_literal: true

module BetterAuth
  module Adapters
    class Postgres < SQL
      attr_reader :url

      def initialize(options = nil, url: nil, connection: nil)
        require "pg" unless connection

        config = options || Configuration.new(secret: Configuration::DEFAULT_SECRET, database: :memory)
        @url = url
        super(config, connection: connection || PG.connect(url), dialect: :postgres)
      end
    end
  end
end
