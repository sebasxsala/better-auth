# frozen_string_literal: true

module BetterAuth
  module Deprecate
    module_function

    def wrap(message, logger: nil, &block)
      warned = false
      proc do |*args, **kwargs|
        unless warned
          warn_once("[Deprecation] #{message}", logger)
          warned = true
        end
        kwargs.empty? ? block.call(*args) : block.call(*args, **kwargs)
      end
    end

    def warn_once(message, logger)
      if logger.respond_to?(:call)
        logger.call(message)
      elsif logger.respond_to?(:warn)
        logger.warn(message)
      else
        warn(message)
      end
    end
  end
end
