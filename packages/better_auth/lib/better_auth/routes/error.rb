# frozen_string_literal: true

require "uri"

module BetterAuth
  module Routes
    def self.error
      Endpoint.new(
        path: "/error",
        method: "GET",
        metadata: {
          hide: true,
          openapi: {
            description: "Displays an error page",
            responses: {
              "200" => OpenAPI.json_response(
                "Success",
                OpenAPI.object_schema(
                  {
                    html: {
                      type: "string",
                      description: "The HTML content of the error page"
                    }
                  },
                  required: ["html"]
                )
              )
            }
          }
        }
      ) do |ctx|
        query = ctx.query || {}
        raw_code = query["error"] || query[:error] || "UNKNOWN"
        raw_description = query["error_description"] || query[:error_description]
        safe_code = valid_error_code?(raw_code) ? raw_code.to_s : "UNKNOWN"
        query_params = error_query_params(safe_code, raw_description)
        error_url = ctx.context.options.on_api_error[:error_url]

        if error_url
          location = append_query(error_url, query_params)
          next [302, {"location" => location}, [""]]
        end

        if ctx.context.options.production? && !ctx.context.options.on_api_error[:customize_default_error_page]
          next [302, {"location" => "/?#{query_params}"}, [""]]
        end

        [
          200,
          {"content-type" => "text/html"},
          [error_html(safe_code, raw_description)]
        ]
      end
    end

    def self.valid_error_code?(value)
      /\A['A-Za-z0-9_-]+\z/.match?(value.to_s)
    end

    def self.error_query_params(code, description)
      params = {error: code}
      params[:error_description] = description if description
      URI.encode_www_form(params)
    end

    def self.append_query(url, query)
      separator = url.include?("?") ? "&" : "?"
      "#{url}#{separator}#{query}"
    end

    def self.error_html(code, description)
      safe_code = sanitize_html(code)
      safe_description = description ? sanitize_html(description) : default_error_description(safe_code)

      <<~HTML
        <!DOCTYPE html>
        <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Error</title>
            <style>
              body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #fff; color: #171717; }
              main { width: min(42rem, calc(100% - 2rem)); border: 2px solid #d4d4d4; padding: 1.5rem; text-align: center; }
              h1 { margin: 0 0 1rem; font-size: 3rem; line-height: 1; }
              code { display: inline-block; border: 1px solid #d4d4d4; padding: 0.375rem 0.75rem; margin-bottom: 1rem; word-break: break-all; }
              p { color: #525252; line-height: 1.5; }
              a { color: inherit; }
              @media (prefers-color-scheme: dark) {
                body { background: #171717; color: #fafafa; }
                main, code { border-color: #404040; }
                p { color: #d4d4d4; }
              }
            </style>
          </head>
          <body>
            <main>
              <h1>ERROR</h1>
              <code>#{safe_code}</code>
              <p>#{safe_description}</p>
            </main>
          </body>
        </html>
      HTML
    end

    def self.default_error_description(code)
      "We encountered an unexpected error. You can find more information about this error at " \
        "<a href=\"https://better-auth.com/docs/reference/errors/#{URI.encode_www_form_component(code)}\">Better Auth docs</a>."
    end

    def self.sanitize_html(value)
      value.to_s
        .gsub("<", "&lt;")
        .gsub(">", "&gt;")
        .gsub('"', "&quot;")
        .gsub("'", "&#39;")
        .gsub(/&(?!(?:amp|lt|gt|quot|#39|#x[0-9a-fA-F]+|#[0-9]+);)/, "&amp;")
    end
  end
end
