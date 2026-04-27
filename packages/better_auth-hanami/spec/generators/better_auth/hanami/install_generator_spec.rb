# frozen_string_literal: true

require_relative "../../../spec_helper"

RSpec.describe BetterAuth::Hanami::Generators::InstallGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-hanami-generator") do |dir|
      @destination = dir
      FileUtils.mkdir_p(File.join(dir, "config"))
      File.write(File.join(dir, "config/routes.rb"), routes_file)
      File.write(File.join(dir, "config/settings.rb"), settings_file)
      example.run
    end
  end

  it "creates provider, migration, task, and route/settings integration" do
    described_class.new(destination_root: @destination).run

    provider = File.join(@destination, "config/providers/better_auth.rb")
    migration = Dir[File.join(@destination, "config/db/migrate/*_create_better_auth_tables.rb")].first
    task = File.join(@destination, "lib/tasks/better_auth.rake")
    app_repo = File.join(@destination, "app/repo.rb")
    users_relation = File.join(@destination, "app/relations/users.rb")
    user_repo = File.join(@destination, "app/repos/user_repo.rb")

    expect(File.read(provider)).to include("Hanami.app.register_provider(:better_auth)")
    expect(File.read(provider)).to include("BetterAuth::Hanami.configure")
    expect(File.read(migration)).to include("ROM::SQL.migration")
    expect(File.read(task)).to include("namespace :generate")
    expect(File.read(task)).to include("task :migration")
    expect(File.read(app_repo)).to include("class Repo < Hanami::DB::Repo")
    expect(File.read(users_relation)).to include("class Users < Hanami::DB::Relation")
    expect(File.read(users_relation)).to include("schema :users, infer: true")
    expect(File.read(user_repo)).to include("class UserRepo < Repo[:users]")
    expect(File.read(File.join(@destination, "config/routes.rb"))).to include("better_auth")
    expect(File.read(File.join(@destination, "config/settings.rb"))).to include("setting :better_auth_secret")
  end

  it "does not overwrite an existing provider" do
    FileUtils.mkdir_p(File.join(@destination, "config/providers"))
    provider = File.join(@destination, "config/providers/better_auth.rb")
    File.write(provider, "# existing\n")

    described_class.new(destination_root: @destination).run

    expect(File.read(provider)).to eq("# existing\n")
  end

  it "does not overwrite existing app repo, relations, or repos" do
    FileUtils.mkdir_p(File.join(@destination, "app/relations"))
    FileUtils.mkdir_p(File.join(@destination, "app/repos"))
    File.write(File.join(@destination, "app/repo.rb"), "# existing repo\n")
    File.write(File.join(@destination, "app/relations/users.rb"), "# existing users relation\n")
    File.write(File.join(@destination, "app/repos/user_repo.rb"), "# existing user repo\n")

    described_class.new(destination_root: @destination).run

    expect(File.read(File.join(@destination, "app/repo.rb"))).to eq("# existing repo\n")
    expect(File.read(File.join(@destination, "app/relations/users.rb"))).to eq("# existing users relation\n")
    expect(File.read(File.join(@destination, "app/repos/user_repo.rb"))).to eq("# existing user repo\n")
  end

  it "creates relations and repos for plugin schema tables configured through BetterAuth::Hanami" do
    BetterAuth::Hanami.configure do |config|
      config.secret = "test-secret-that-is-long-enough-for-validation"
      config.database = :memory
      config.plugins = [
        BetterAuth::Plugin.new(
          id: "audit",
          schema: {
            auditLog: {
              model_name: "audit_logs",
              fields: {
                id: {type: "string", required: true},
                action: {type: "string", required: true}
              }
            }
          }
        )
      ]
    end

    described_class.new(destination_root: @destination).run

    audit_relation = File.join(@destination, "app/relations/audit_logs.rb")
    audit_repo = File.join(@destination, "app/repos/audit_log_repo.rb")
    expect(File.read(audit_relation)).to include("class AuditLogs < Hanami::DB::Relation")
    expect(File.read(audit_relation)).to include("schema :audit_logs, infer: true")
    expect(File.read(audit_repo)).to include("class AuditLogRepo < Repo[:audit_logs]")
  ensure
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  def routes_file
    <<~RUBY
      # frozen_string_literal: true

      module Bookshelf
        class Routes < Hanami::Routes
        end
      end
    RUBY
  end

  def settings_file
    <<~RUBY
      # frozen_string_literal: true

      module Bookshelf
        class Settings < Hanami::Settings
        end
      end
    RUBY
  end
end
