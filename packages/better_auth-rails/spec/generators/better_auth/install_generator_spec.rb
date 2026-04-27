# frozen_string_literal: true

require "tmpdir"
require_relative "../../spec_helper"
require "generators/better_auth/install/install_generator"

RSpec.describe BetterAuth::Generators::InstallGenerator do
  around do |example|
    Dir.mktmpdir("better-auth-rails-generator") do |dir|
      @destination = dir
      example.run
    end
  end

  it "creates the initializer and base migration" do
    described_class.start(["--database=postgresql"], destination_root: @destination)

    initializer = File.join(@destination, "config/initializers/better_auth.rb")
    migrations = Dir[File.join(@destination, "db/migrate/*_create_better_auth_tables.rb")]

    expect(File.read(initializer)).to include("BetterAuth::Rails.configure")
    expect(File.read(initializer)).to include("ActiveRecordAdapter")
    expect(File.read(initializer)).to include("config.trusted_origins")
    expect(File.read(initializer)).to include("config.session")
    expect(File.read(initializer)).to include("strategy: \"jwe\"")
    expect(File.read(initializer)).to include("config.advanced")
    expect(File.read(initializer)).to include("config.experimental")
    expect(File.read(initializer)).to include("config.social_providers")
    expect(File.read(initializer)).to include("config.plugins")
    expect(File.read(initializer)).to include("config.hooks")
    expect(migrations.length).to eq(1)
    expect(File.read(migrations.first)).to include("create_table :users, id: false")
  end

  it "does not overwrite an existing initializer" do
    path = File.join(@destination, "config/initializers")
    FileUtils.mkdir_p(path)
    initializer = File.join(path, "better_auth.rb")
    File.write(initializer, "# existing\n")

    described_class.start([], destination_root: @destination)

    expect(File.read(initializer)).to eq("# existing\n")
  end
end
