# frozen_string_literal: true

require "test_helper"

class BetterAuthInstrumentationTest < Minitest::Test
  def test_noop_span_mutators_are_safe_and_with_span_returns_result
    result = BetterAuth::Instrumentation.with_span("test.span", attributes: {"key" => "value"}) do |span|
      span.set_attribute("other", "value")
      span.record_exception(RuntimeError.new("boom"))
      span.set_status(BetterAuth::Instrumentation::SpanStatusCode::OK)
      "result"
    end

    assert_equal "result", result
  end

  def test_with_span_records_error_status_and_reraises
    error = assert_raises(RuntimeError) do
      BetterAuth::Instrumentation.with_span("test.error") { raise "boom" }
    end

    assert_equal "boom", error.message
  end

  def test_noop_trace_surface_exposes_active_span_and_tracer
    tracer = BetterAuth::Instrumentation.trace.get_tracer("better-auth")
    assert_respond_to tracer, :start_active_span
    assert_instance_of BetterAuth::Instrumentation::NoopSpan, BetterAuth::Instrumentation.trace.get_active_span
  end
end
