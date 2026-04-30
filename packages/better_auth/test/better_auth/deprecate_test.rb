# frozen_string_literal: true

require "test_helper"

class BetterAuthDeprecateTest < Minitest::Test
  def test_deprecate_warns_once_and_preserves_return_value
    warnings = []
    wrapped = BetterAuth::Deprecate.wrap("old API", logger: ->(message) { warnings << message }) do |value|
      value.upcase
    end

    assert_equal "VALUE", wrapped.call("value")
    assert_equal "OTHER", wrapped.call("other")
    assert_equal ["[Deprecation] old API"], warnings
  end

  def test_deprecate_supports_logger_warn_method
    logger = Class.new do
      attr_reader :warnings

      def initialize
        @warnings = []
      end

      def warn(message)
        @warnings << message
      end
    end.new

    BetterAuth::Deprecate.wrap("message", logger: logger) { :ok }.call

    assert_equal ["[Deprecation] message"], logger.warnings
  end
end
