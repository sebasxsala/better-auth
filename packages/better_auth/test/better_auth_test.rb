# frozen_string_literal: true

require_relative "test_helper"

class BetterAuthTest < Minitest::Test
  def test_version
    refute_nil BetterAuth::VERSION
  end
end
