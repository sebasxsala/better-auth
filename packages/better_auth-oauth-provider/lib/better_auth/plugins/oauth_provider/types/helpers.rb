# frozen_string_literal: true

module BetterAuth
  module Plugins
    module OAuthProvider
      module Types
        module Helpers
          module_function

          def callable?(value)
            value.respond_to?(:call)
          end

          def string_array(value)
            Array(value).map(&:to_s).reject(&:empty?)
          end
        end
      end
    end
  end
end
