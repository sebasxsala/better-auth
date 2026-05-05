# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.ok
      Endpoint.new(
        path: "/ok",
        method: "GET",
        metadata: {
          hide: true,
          openapi: {
            description: "Check if the API is working",
            responses: {
              "200" => OpenAPI.json_response(
                "API is working",
                OpenAPI.object_schema(
                  {
                    ok: {
                      type: "boolean",
                      description: "Indicates if the API is working"
                    }
                  },
                  required: ["ok"]
                )
              )
            }
          }
        }
      ) do |ctx|
        ctx.json({ok: true})
      end
    end
  end
end
