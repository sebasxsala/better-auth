# frozen_string_literal: true

require "better_auth"
require_relative "api_key/version"
require_relative "plugins/api_key"

module BetterAuth
  module APIKey
    module_function

    def default_key_hasher(key)
      Plugins.default_api_key_hasher(key)
    end
  end
end
