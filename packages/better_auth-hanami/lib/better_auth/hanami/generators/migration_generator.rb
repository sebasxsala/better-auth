# frozen_string_literal: true

require "fileutils"
require "time"

module BetterAuth
  module Hanami
    module Generators
      class MigrationGenerator
        def initialize(destination_root: Dir.pwd, configuration: nil)
          @destination_root = destination_root
          @configuration = configuration
        end

        def run
          return migration_path if existing_migration?

          FileUtils.mkdir_p(File.dirname(migration_path))
          File.write(migration_path, BetterAuth::Hanami::Migration.render(generator_config))
          migration_path
        end

        private

        attr_reader :destination_root, :configuration

        def existing_migration?
          Dir[File.join(destination_root, "config/db/migrate/*_create_better_auth_tables.rb")].any?
        end

        def migration_path
          @migration_path ||= File.join(destination_root, "config/db/migrate", "#{timestamp}_create_better_auth_tables.rb")
        end

        def timestamp
          Time.now.utc.strftime("%Y%m%d%H%M%S")
        end

        def generator_config
          return configuration if configuration

          options = BetterAuth::Hanami.configuration.to_auth_options
          options[:secret] ||= BetterAuth::Configuration::DEFAULT_SECRET
          options[:database] ||= :memory
          BetterAuth::Configuration.new(options)
        end
      end
    end
  end
end
