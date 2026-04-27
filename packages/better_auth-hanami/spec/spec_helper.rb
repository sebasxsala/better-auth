# frozen_string_literal: true

require "bundler/setup"
require "json"
require "rack/mock"
require "sequel"
require "stringio"
require "tmpdir"
require "fileutils"
require "better_auth/hanami"
require "better_auth_hanami"

RSpec.configure do |config|
  config.example_status_persistence_file_path = ".rspec_status"
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
