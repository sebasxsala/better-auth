# frozen_string_literal: true

require "test_helper"

class BetterAuthAsyncTest < Minitest::Test
  def test_map_concurrent_returns_empty_without_invoking_mapper
    called = false

    assert_equal [], BetterAuth::Async.map_concurrent([], concurrency: 2) { called = true }
    refute called
  end

  def test_map_concurrent_preserves_order_and_passes_index
    result = BetterAuth::Async.map_concurrent([3, 2, 1], concurrency: 3) do |item, index|
      sleep item * 0.005
      "#{index}:#{item}"
    end

    assert_equal ["0:3", "1:2", "2:1"], result
  end

  def test_map_concurrent_clamps_concurrency
    active = 0
    max_active = 0
    mutex = Mutex.new

    BetterAuth::Async.map_concurrent([1, 2, 3, 4], concurrency: 2.8) do
      mutex.synchronize do
        active += 1
        max_active = [max_active, active].max
      end
      sleep 0.01
      mutex.synchronize { active -= 1 }
    end

    assert_equal 2, max_active
    assert_equal [2, 1, 1], [max_active, BetterAuth::Async.send(:normalized_concurrency, 0, 4), BetterAuth::Async.send(:normalized_concurrency, -5, 4)]
  end

  def test_map_concurrent_fails_fast_on_mapper_error
    error = assert_raises(RuntimeError) do
      BetterAuth::Async.map_concurrent([1, 2, 3], concurrency: 1) do |item|
        raise "boom" if item == 2
        item
      end
    end

    assert_equal "boom", error.message
  end

  def test_map_concurrent_raises_before_waiting_for_slow_in_flight_work
    slow_started = Queue.new
    started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    error = assert_raises(RuntimeError) do
      BetterAuth::Async.map_concurrent([:slow, :fail], concurrency: 2) do |item|
        if item == :slow
          slow_started << true
          sleep 1
        else
          slow_started.pop
          raise "boom"
        end
      end
    end

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
    assert_equal "boom", error.message
    assert_operator elapsed, :<, 0.5
  end
end
