# frozen_string_literal: true

require "rails/generators"
require "better_auth/rails"
require "generators/better_auth/migration/migration_generator"

module BetterAuth
  module Generators
    class InstallGenerator < ::Rails::Generators::Base
      source_root File.expand_path("templates", __dir__)
      class_option :database, type: :string, default: "active_record"

      def create_initializer
        initializer = "config/initializers/better_auth.rb"
        if File.exist?(destination_path(initializer))
          say_status :skip, "#{initializer} already exists"
          return
        end

        template "initializer.rb.tt", initializer
      end

      def create_migration
        MigrationGenerator.start([], destination_root: destination_root)
      end

      private

      def destination_path(path)
        File.join(destination_root, path)
      end
    end
  end
end
