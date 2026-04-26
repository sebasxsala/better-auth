# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"
require "generators/better_auth/migration/migration_generator"

RSpec.describe BetterAuth::Generators::MigrationGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-rails-migration-generator") do |dir|
      @destination = dir
      example.run
    end
  end

  it "creates the Better Auth base migration" do
    described_class.start([], destination_root: @destination)

    migrations = Dir[File.join(@destination, "db/migrate/*_create_better_auth_tables.rb")]

    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("class CreateBetterAuthTables < ActiveRecord::Migration")
  end

  it "does not create a duplicate base migration" do
    path = File.join(@destination, "db/migrate")
    FileUtils.mkdir_p(path)
    File.write(File.join(path, "20260425000000_create_better_auth_tables.rb"), "# existing\n")

    described_class.start([], destination_root: @destination)

    expect(Dir[File.join(path, "*_create_better_auth_tables.rb")].length).to eq(1)
  end
end
