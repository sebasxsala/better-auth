# frozen_string_literal: true

require "uri"

module BetterAuth
  module Adapters
    class MySQL < SQL
      attr_reader :url

      def initialize(options = nil, url: nil, connection: nil)
        require "mysql2" unless connection

        config = options || Configuration.new(secret: Configuration::DEFAULT_SECRET, database: :memory)
        @url = url
        super(config, connection: connection || Mysql2::Client.new(mysql_options(url)), dialect: :mysql)
      end

      private

      def mysql_options(url)
        uri = URI.parse(url.to_s)
        {
          host: uri.host,
          port: uri.port || 3306,
          username: URI.decode_www_form_component(uri.user.to_s),
          password: URI.decode_www_form_component(uri.password.to_s),
          database: uri.path.to_s.delete_prefix("/"),
          symbolize_keys: false
        }.compact
      end
    end
  end
end
