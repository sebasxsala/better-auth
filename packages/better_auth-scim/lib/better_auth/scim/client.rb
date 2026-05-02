# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_client
      {
        "id" => "scim-client",
        "version" => BetterAuth::SCIM::VERSION,
        "serverPluginId" => "scim"
      }
    end
  end
end
