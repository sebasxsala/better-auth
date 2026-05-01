# frozen_string_literal: true

module BetterAuth
  module Plugins
    module MCP
      module ResourceHandler
        module_function

        def with_mcp_auth(app, resource_metadata_url:, auth: nil, resource_metadata_mappings: {})
          lambda do |env|
            authorization = env["HTTP_AUTHORIZATION"].to_s
            return unauthorized(resource_metadata_url) unless authorization.start_with?("Bearer ")

            session = auth&.api&.get_mcp_session(headers: {"authorization" => authorization})
            return unauthorized(resource_metadata_url) unless session

            env["better_auth.mcp_session"] = session
            app.call(env)
          rescue APIError
            unauthorized(resource_metadata_url)
          end
        end

        def unauthorized(resource_metadata_url)
          [
            401,
            {
              "www-authenticate" => %(Bearer resource_metadata="#{resource_metadata_url}"),
              "access-control-expose-headers" => "WWW-Authenticate"
            },
            ["unauthorized"]
          ]
        end
      end
    end
  end
end
