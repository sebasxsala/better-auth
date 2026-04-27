# frozen_string_literal: true

require "fileutils"

module BetterAuth
  module Hanami
    module Generators
      class RelationGenerator
        def initialize(destination_root: Dir.pwd, configuration: nil)
          @destination_root = destination_root
          @configuration = configuration
        end

        def run
          create_base_repo
          generator_config && tables.each_value do |table|
            create_relation(table)
            create_repo(table)
          end
        end

        private

        attr_reader :destination_root, :configuration

        def create_base_repo
          path = File.join(destination_root, "app/repo.rb")
          return if File.exist?(path)

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, base_repo_template)
        end

        def create_relation(table)
          table_name = table.fetch(:model_name)
          path = File.join(destination_root, "app/relations", "#{table_name}.rb")
          return if File.exist?(path)

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, relation_template(table_name))
        end

        def create_repo(table)
          table_name = table.fetch(:model_name)
          path = File.join(destination_root, "app/repos", "#{singular_name(table_name)}_repo.rb")
          return if File.exist?(path)

          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, repo_template(table_name))
        end

        def tables
          BetterAuth::Schema.auth_tables(generator_config)
        end

        def generator_config
          @generator_config ||= begin
            return configuration if configuration

            options = BetterAuth::Hanami.configuration.to_auth_options
            options[:secret] ||= BetterAuth::Configuration::DEFAULT_SECRET
            options[:database] ||= :memory
            BetterAuth::Configuration.new(options)
          end
        end

        def app_namespace
          @app_namespace ||= begin
            candidates = [
              File.join(destination_root, "config/app.rb"),
              File.join(destination_root, "config/routes.rb"),
              File.join(destination_root, "config/settings.rb")
            ]
            candidates.filter_map do |path|
              next unless File.exist?(path)

              File.read(path).match(/module\s+([A-Z][A-Za-z0-9_:]*)/)&.[](1)
            end.first || "Main"
          end
        end

        def base_repo_template
          <<~RUBY
            # frozen_string_literal: true

            module #{app_namespace}
              class Repo < Hanami::DB::Repo
              end
            end
          RUBY
        end

        def relation_template(table_name)
          <<~RUBY
            # frozen_string_literal: true

            module #{app_namespace}
              module Relations
                class #{class_name(table_name)} < Hanami::DB::Relation
                  schema :#{table_name}, infer: true
                end
              end
            end
          RUBY
        end

        def repo_template(table_name)
          <<~RUBY
            # frozen_string_literal: true

            module #{app_namespace}
              module Repos
                class #{class_name(singular_name(table_name))}Repo < Repo[:#{table_name}]
                end
              end
            end
          RUBY
        end

        def class_name(value)
          value.to_s.split("_").map(&:capitalize).join
        end

        def singular_name(value)
          value.to_s.sub(/ies\z/, "y").sub(/s\z/, "")
        end
      end
    end
  end
end
