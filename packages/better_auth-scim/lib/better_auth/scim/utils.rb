# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def scim_param(ctx, key)
      ctx.params[key] || ctx.params[key.to_s] || ctx.params[Schema.storage_key(key)] || ctx.params[Schema.storage_key(key).to_sym]
    end

    def scim_resource_url(base_url, path)
      return path unless base_url

      "#{base_url}#{path}"
    end
  end
end
