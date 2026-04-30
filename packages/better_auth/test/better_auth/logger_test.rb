# frozen_string_literal: true

require "test_helper"

class BetterAuthLoggerTest < Minitest::Test
  def test_should_publish_log_matches_upstream_log_level_order
    levels = [:debug, :info, :success, :warn, :error]

    levels.each_with_index do |current, current_index|
      levels.each_with_index do |level, level_index|
        assert_equal level_index >= current_index, BetterAuth::Logger.should_publish?(current, level), "#{current} -> #{level}"
      end
    end
  end

  def test_create_logger_respects_level_disabled_and_custom_handler
    entries = []
    logger = BetterAuth::Logger.create(level: :warn, log: ->(level, message, *args) { entries << [level, message, args] })

    logger.info("hidden")
    logger.success("hidden")
    logger.warn("visible", 1)
    logger.error("bad")

    assert_equal [[:warn, "visible", [1]], [:error, "bad", []]], entries

    disabled_entries = []
    disabled = BetterAuth::Logger.create(disabled: true, log: ->(*args) { disabled_entries << args })
    disabled.error("hidden")
    assert_empty disabled_entries
  end

  def test_default_logger_emits_enabled_verbose_messages
    logger = BetterAuth::Logger.create(level: :debug)

    _out, err = capture_io do
      logger.debug("debug visible")
      logger.info("info visible")
      logger.success("success visible")
      logger.warn("warn visible")
      logger.error("error visible")
    end

    assert_includes err, "DEBUG [Better Auth]: debug visible"
    assert_includes err, "INFO [Better Auth]: info visible"
    assert_includes err, "SUCCESS [Better Auth]: success visible"
    assert_includes err, "WARN [Better Auth]: warn visible"
    assert_includes err, "ERROR [Better Auth]: error visible"
  end
end
