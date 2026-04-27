# frozen_string_literal: true

require_relative "../../../spec_helper"

RSpec.describe BetterAuth::Hanami::Generators::RelationGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-hanami-relation-generator") do |dir|
      @destination = dir
      FileUtils.mkdir_p(File.join(dir, "config"))
      File.write(File.join(dir, "config/routes.rb"), routes_file)
      example.run
    end
  ensure
    BetterAuth::Hanami.instance_variable_set(:@auth, nil)
    BetterAuth::Hanami.instance_variable_set(:@configuration, nil)
  end

  it "creates the base app repo, auth relations, and auth repos" do
    described_class.new(destination_root: @destination).run

    expect(File.read(File.join(@destination, "app/repo.rb"))).to include("module Bookshelf")
    expect(File.read(File.join(@destination, "app/repo.rb"))).to include("class Repo < Hanami::DB::Repo")
    expect(File.read(File.join(@destination, "app/relations/users.rb"))).to include("class Users < Hanami::DB::Relation")
    expect(File.read(File.join(@destination, "app/repos/user_repo.rb"))).to include("class UserRepo < Repo[:users]")
    expect(File.read(File.join(@destination, "app/repos/verification_repo.rb"))).to include("class VerificationRepo < Repo[:verifications]")
  end

  it "creates relation and repo files for configured plugin tables" do
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
                id: {type: "string", required: true}
              }
            }
          }
        )
      ]
    end

    described_class.new(destination_root: @destination).run

    expect(File.read(File.join(@destination, "app/relations/audit_logs.rb"))).to include("schema :audit_logs, infer: true")
    expect(File.read(File.join(@destination, "app/repos/audit_log_repo.rb"))).to include("class AuditLogRepo < Repo[:audit_logs]")
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
end
