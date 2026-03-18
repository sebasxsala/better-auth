# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "better_auth"

require "minitest/autorun"
require "minitest/spec"

# Configure SimpleCov if running coverage
if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/test/"
  end
end
