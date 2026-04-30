# frozen_string_literal: true

module BetterAuth
  module Async
    module_function

    def map_concurrent(items, concurrency:, &mapper)
      list = items.to_a
      return [] if list.empty?

      width = normalized_concurrency(concurrency, list.length)
      results = Array.new(list.length)
      next_index = 0
      first_error = nil
      mutex = Mutex.new
      status = Queue.new

      workers = Array.new(width) do
        Thread.new do
          loop do
            index = mutex.synchronize do
              break if first_error || next_index >= list.length

              current = next_index
              next_index += 1
              current
            end
            break unless index

            begin
              results[index] = mapper.call(list[index], index)
            rescue => error
              mutex.synchronize { first_error ||= error }
              status << [:error, error]
              break
            end
          end
        ensure
          status << [:done, nil]
        end
      end

      done = 0
      while done < workers.length
        type, error = status.pop
        if type == :error
          workers.each { |worker| worker.kill if worker.alive? }
          workers.each(&:join)
          raise error
        end

        done += 1
      end

      raise first_error if first_error

      results
    end

    def normalized_concurrency(concurrency, item_count)
      raw = begin
        Float(concurrency).floor
      rescue ArgumentError, TypeError
        1
      end
      raw = 1 if raw < 1
      [raw, item_count].min
    end
  end
end
