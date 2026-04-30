# frozen_string_literal: true

require "test_helper"

class BetterAuthRequestStateTest < Minitest::Test
  def test_request_state_runs_function_with_isolated_store
    state = BetterAuth::RequestState.define { [] }

    first = BetterAuth::RequestState.run do
      state.get << "first"
      state.get
    end
    second = BetterAuth::RequestState.run do
      state.get << "second"
      state.get
    end

    assert_equal ["first"], first
    assert_equal ["second"], second
  end

  def test_request_state_supports_nested_operations_and_set
    state = BetterAuth::RequestState.define { "initial" }

    result = BetterAuth::RequestState.run do
      assert BetterAuth::RequestState.present?
      state.set("changed")
      state.get
    end

    assert_equal "changed", result
    refute BetterAuth::RequestState.present?
  end

  def test_request_state_raises_outside_context
    state = BetterAuth::RequestState.define { "value" }

    error = assert_raises(RuntimeError) { state.get }
    assert_match "No request state found", error.message
  end

  def test_request_state_is_thread_isolated
    state = BetterAuth::RequestState.define { [] }

    queues = 2.times.map do |index|
      Thread.new do
        BetterAuth::RequestState.run do
          state.get << index
          sleep 0.01
          state.get
        end
      end
    end

    assert_equal [[0], [1]], queues.map(&:value)
  end
end
