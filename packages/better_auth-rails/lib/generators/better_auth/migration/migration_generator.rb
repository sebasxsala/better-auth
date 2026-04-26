# frozen_string_literal: true

require "rails/generators"
require "better_auth/rails"

module BetterAuth
  module Generators
    class MigrationGenerator < ::Rails::Generators::Base
      def create_migration
        if existing_migration?
          say_status :skip, "db/migrate/*_create_better_auth_tables.rb already exists"
          return
        end

        create_file migration_path, BetterAuth::Rails::Migration.render(generator_config)
      end

      private

      def existing_migration?
        Dir[File.join(destination_root, "db/migrate/*_create_better_auth_tables.rb")].any?
      end

      def migration_path
        File.join("db/migrate", "#{timestamp}_create_better_auth_tables.rb")
      end

      def timestamp
        Time.now.utc.strftime("%Y%m%d%H%M%S")
      end

      def generator_config
        BetterAuth::Configuration.new(secret: BetterAuth::Configuration::DEFAULT_SECRET, database: :memory)
      end
    end
  end
end
