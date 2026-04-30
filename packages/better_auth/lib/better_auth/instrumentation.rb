# frozen_string_literal: true

module BetterAuth
  module Instrumentation
    module SpanStatusCode
      UNSET = 0
      OK = 1
      ERROR = 2
    end

    class NoopSpan
      def set_attribute(_key, _value)
        self
      end

      def set_attributes(_attributes)
        self
      end

      def record_exception(_error)
        self
      end

      def set_status(_status)
        self
      end

      def add_event(_name, _attributes = nil)
        self
      end

      def end
        self
      end
    end

    class NoopTracer
      def start_active_span(_name, attributes: {}, &block)
        span = NoopSpan.new
        return span unless block

        block.call(span)
      ensure
        span&.end
      end
    end

    class Trace
      def get_tracer(_name = "better-auth")
        NoopTracer.new
      end

      def get_active_span
        NoopSpan.new
      end
    end

    module_function

    def trace
      @trace ||= Trace.new
    end

    def with_span(name, attributes: {}, &block)
      trace.get_tracer("better-auth").start_active_span(name, attributes: attributes) do |span|
        block.call(span)
      rescue => error
        span.record_exception(error)
        span.set_status(SpanStatusCode::ERROR)
        raise
      end
    end
  end
end
