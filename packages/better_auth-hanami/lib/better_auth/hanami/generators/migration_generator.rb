# frozen_string_literal: true

require "fileutils"
require "time"

module BetterAuth
  module Hanami
    module Generators
      class MigrationGenerator
        def initialize(destination_root: Dir.pwd, configuration: nil, force: false)
          @destination_root = destination_root
          @configuration = configuration
          @force = force
        end

        def run(force: nil)
          force = @force if force.nil?
          return existing_migration_path if existing_migration_path && !force

          path = existing_migration_path || migration_path
          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, BetterAuth::Hanami::Migration.render(generator_config))
          path
        end

        private

        attr_reader :destination_root, :configuration

        def existing_migration_path
          @existing_migration_path ||= Dir[File.join(destination_root, "config/db/migrate/*_create_better_auth_tables.rb")].min
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
