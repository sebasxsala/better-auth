# frozen_string_literal: true

module BetterAuth
  module Plugins
    module_function

    def open_api(options = {})
      config = {path: "/reference", theme: "default"}.merge(normalize_hash(options))

      Plugin.new(
        id: "open-api",
        endpoints: {
          generate_open_api_schema: Endpoint.new(path: "/open-api/generate-schema", method: "GET") do |ctx|
            ctx.json(open_api_schema(ctx.context))
          end,
          open_api_reference: Endpoint.new(path: config[:path], method: "GET", metadata: {hide: true}) do |ctx|
            raise APIError.new("NOT_FOUND") if config[:disable_default_reference]

            [200, {"content-type" => "text/html"}, [open_api_html(open_api_schema(ctx.context), config)]]
          end
        },
        options: config
      )
    end

    def open_api_schema(context)
      {
        openapi: "3.1.1",
        info: {
          title: "Better Auth",
          description: "API Reference for your Better Auth Instance",
          version: "1.1.0"
        },
        components: {
          schemas: open_api_components(context.options),
          securitySchemes: open_api_security_schemes
        },
        security: [
          {
            apiKeyCookie: [],
            bearerAuth: []
          }
        ],
        servers: [
          {
            url: context.base_url
          }
        ],
        tags: [
          {
            name: "Default",
            description: "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin."
          }
        ],
        paths: open_api_paths(open_api_endpoints(context.options), context.options)
      }
    end

    def open_api_endpoints(options)
      Core.base_endpoints.map { |key, endpoint| [key, endpoint, "Default"] } +
        options.plugins.flat_map do |plugin|
          next [] if plugin.id == "open-api"

          tag = plugin.id.to_s.split("-").map(&:capitalize).join("-")
          plugin.endpoints.map { |key, endpoint| [key, endpoint, tag] }
        end
    end

    def open_api_security_schemes
      {
        apiKeyCookie: {
          type: "apiKey",
          in: "cookie",
          name: "apiKeyCookie",
          description: "API Key authentication via cookie"
        },
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          description: "Bearer token authentication"
        }
      }
    end

    def open_api_paths(endpoints, options)
      disabled_paths = Array(options.disabled_paths).map(&:to_s)
      endpoints.each_with_object({}) do |(_key, endpoint, tag), paths|
        next unless endpoint.path
        next if endpoint.metadata[:hide] || endpoint.metadata[:SERVER_ONLY] || endpoint.metadata[:server_only]
        next if disabled_paths.include?(endpoint.path)

        path = open_api_path(endpoint.path)
        paths[path] ||= {}
        endpoint.methods.reject { |method| method == "*" }.each do |method|
          paths[path][method.downcase.to_sym] = open_api_operation(endpoint, method, tag)
        end
      end
    end

    def open_api_path(path)
      path.split("/").map { |part| part.start_with?(":") ? "{#{part.delete_prefix(":")}}" : part }.join("/")
    end

    def open_api_operation(endpoint, method, tag)
      metadata = endpoint.metadata[:openapi] || {}
      operation = {
        tags: Array(metadata[:tags] || [tag]),
        description: metadata[:description] || route_description(endpoint.path, method),
        operationId: metadata.key?(:operationId) ? metadata[:operationId] : route_operation_id(endpoint.path, method),
        security: [
          {
            bearerAuth: []
          }
        ],
        parameters: metadata[:parameters] || [],
        responses: open_api_responses(metadata[:responses] || route_responses(endpoint.path, method))
      }

      if %w[POST PATCH PUT].include?(method)
        operation[:requestBody] = metadata[:requestBody] || route_request_body(endpoint.path, method) || empty_request_body
      end

      operation
    end

    def route_description(path, method)
      route_open_api_metadata(path, method)[:description]
    end

    def route_operation_id(path, method)
      route_open_api_metadata(path, method)[:operationId]
    end

    def route_request_body(path, method)
      route_open_api_metadata(path, method)[:requestBody]
    end

    def route_responses(path, method)
      route_open_api_metadata(path, method)[:responses]
    end

    def route_open_api_metadata(path, method)
      case [path, method.to_s.upcase]
      when ["/change-email", "POST"]
        {
          operationId: "changeEmail",
          requestBody: {
            required: true,
            content: {
              "application/json" => {
                schema: object_schema(
                  {
                    callbackURL: {type: ["string", "null"], description: "The URL to redirect to after email verification"},
                    newEmail: {type: "string", description: "The new email address to set must be a valid email address"}
                  },
                  required: ["newEmail"]
                )
              }
            }
          },
          responses: {
            "200" => {
              description: "Email change request processed successfully",
              content: {
                "application/json" => {
                  schema: object_schema(
                    {
                      message: {
                        type: "string",
                        nullable: true,
                        enum: ["Email updated", "Verification email sent"],
                        description: "Status message of the email change process"
                      },
                      status: {type: "boolean", description: "Indicates if the request was successful"},
                      user: {type: "object", "$ref": "#/components/schemas/User"}
                    },
                    required: ["status"]
                  )
                }
              }
            },
            "422" => error_response("Unprocessable Entity. Email already exists")
          }
        }
      when ["/change-password", "POST"]
        {
          description: "Change the password of the user",
          operationId: "changePassword",
          requestBody: {
            required: true,
            content: {
              "application/json" => {
                schema: object_schema(
                  {
                    newPassword: {type: "string", description: "The new password to set"},
                    currentPassword: {type: "string", description: "The current password is required"},
                    revokeOtherSessions: {type: ["boolean", "null"], description: "Must be a boolean value"}
                  },
                  required: ["newPassword", "currentPassword"]
                )
              }
            }
          },
          responses: {
            "200" => {
              description: "Password successfully changed",
              content: {
                "application/json" => {
                  schema: object_schema(
                    {
                      token: {type: "string", nullable: true, description: "New session token if other sessions were revoked"},
                      user: open_api_user_response_schema
                    },
                    required: ["user"]
                  )
                }
              }
            }
          }
        }
      when ["/sign-in/email", "POST"]
        {
          description: "Sign in with email and password",
          operationId: "signInEmail",
          requestBody: {
            required: true,
            content: {
              "application/json" => {
                schema: object_schema(
                  {
                    email: {type: "string", description: "Email of the user"},
                    password: {type: "string", description: "Password of the user"},
                    callbackURL: {type: ["string", "null"], description: "Callback URL to use as a redirect for email verification"},
                    rememberMe: {type: ["boolean", "null"], default: true, description: "If this is false, the session will not be remembered. Default is `true`."}
                  },
                  required: ["email", "password"]
                )
              }
            }
          },
          responses: {
            "200" => {
              description: "Success - Returns either session details or redirect URL",
              content: {
                "application/json" => {
                  schema: session_response_schema(description: "Session response when idToken is provided", nullable_url: true)
                }
              }
            }
          }
        }
      when ["/sign-in/social", "POST"]
        {
          description: "Sign in with a social provider",
          operationId: "socialSignIn",
          requestBody: {
            required: true,
            content: {
              "application/json" => {
                schema: object_schema(
                  {
                    provider: {type: "string"},
                    callbackURL: {type: ["string", "null"], description: "Callback URL to redirect to after the user has signed in"},
                    errorCallbackURL: {type: ["string", "null"], description: "Callback URL to redirect to if an error happens"},
                    newUserCallbackURL: {type: ["string", "null"]},
                    disableRedirect: {type: ["boolean", "null"], description: "Disable automatic redirection to the provider. Useful for handling the redirection yourself"},
                    requestSignUp: {type: ["boolean", "null"], description: "Explicitly request sign-up. Useful when disableImplicitSignUp is true for this provider"},
                    loginHint: {type: ["string", "null"], description: "The login hint to use for the authorization code request"},
                    additionalData: {type: ["string", "null"]},
                    scopes: {type: ["array", "null"], description: "Array of scopes to request from the provider. This will override the default scopes passed."},
                    idToken: {
                      type: ["object", "null"],
                      properties: {
                        token: {type: "string", description: "ID token from the provider"},
                        accessToken: {type: ["string", "null"], description: "Access token from the provider"},
                        refreshToken: {type: ["string", "null"], description: "Refresh token from the provider"},
                        expiresAt: {type: ["number", "null"], description: "Expiry date of the token"},
                        nonce: {type: ["string", "null"], description: "Nonce used to generate the token"}
                      },
                      required: ["token"]
                    }
                  },
                  required: ["provider"]
                )
              }
            }
          },
          responses: {
            "200" => {
              description: "Success - Returns either session details or redirect URL",
              content: {
                "application/json" => {
                  schema: session_response_schema(description: "Session response when idToken is provided")
                }
              }
            }
          }
        }
      when ["/sign-up/email", "POST"]
        {
          description: "Sign up a user using email and password",
          operationId: "signUpWithEmailAndPassword",
          requestBody: {
            content: {
              "application/json" => {
                schema: object_schema(
                  {
                    name: {type: "string", description: "The name of the user"},
                    email: {type: "string", description: "The email of the user"},
                    password: {type: "string", description: "The password of the user"},
                    image: {type: "string", description: "The profile image URL of the user"},
                    callbackURL: {type: "string", description: "The URL to use for email verification callback"},
                    rememberMe: {type: "boolean", description: "If this is false, the session will not be remembered. Default is `true`."}
                  },
                  required: ["name", "email", "password"]
                )
              }
            }
          },
          responses: {
            "200" => {
              description: "Successfully created user",
              content: {
                "application/json" => {
                  schema: object_schema(
                    {
                      token: {type: "string", nullable: true, description: "Authentication token for the session"},
                      user: {type: "object", "$ref": "#/components/schemas/User"}
                    },
                    required: ["user"]
                  )
                }
              }
            },
            "422" => error_response("Unprocessable Entity. User already exists or failed to create user.")
          }
        }
      else
        {}
      end
    end

    def object_schema(properties, required: [])
      {
        type: "object",
        properties: properties,
        required: required
      }
    end

    def session_response_schema(description:, nullable_url: false)
      object_schema(
        {
          redirect: {type: "boolean", enum: [false]},
          token: {type: "string", description: "Session token"},
          url: nullable_url ? {type: "string", nullable: true} : {type: "string"},
          user: {type: "object", "$ref": "#/components/schemas/User"}
        },
        required: ["redirect", "token", "user"]
      ).merge(description: description)
    end

    def open_api_user_response_schema
      object_schema(
        {
          id: {type: "string", description: "The unique identifier of the user"},
          email: {type: "string", format: "email", description: "The email address of the user"},
          name: {type: "string", description: "The name of the user"},
          image: {type: "string", format: "uri", nullable: true, description: "The profile image URL of the user"},
          emailVerified: {type: "boolean", description: "Whether the email has been verified"},
          createdAt: {type: "string", format: "date-time", description: "When the user was created"},
          updatedAt: {type: "string", format: "date-time", description: "When the user was last updated"}
        },
        required: ["id", "email", "name", "emailVerified", "createdAt", "updatedAt"]
      )
    end

    def empty_request_body
      {
        content: {
          "application/json" => {
            schema: {
              type: "object",
              properties: {}
            }
          }
        }
      }
    end

    def open_api_responses(responses = nil)
      {"200" => success_response}.merge(default_error_responses).merge(responses || {})
    end

    def success_response
      {
        description: "Success",
        content: {
          "application/json" => {
            schema: {
              type: "object",
              properties: {}
            }
          }
        }
      }
    end

    def default_error_responses
      {
        "400" => error_response("Bad Request. Usually due to missing parameters, or invalid parameters.", required: true),
        "401" => error_response("Unauthorized. Due to missing or invalid authentication.", required: true),
        "403" => error_response("Forbidden. You do not have permission to access this resource or to perform this action."),
        "404" => error_response("Not Found. The requested resource was not found."),
        "429" => error_response("Too Many Requests. You have exceeded the rate limit. Try again later."),
        "500" => error_response("Internal Server Error. This is a problem with the server that you cannot fix.")
      }
    end

    def error_response(description, required: false)
      schema = {
        type: "object",
        properties: {
          message: {
            type: "string"
          }
        }
      }
      schema[:required] = ["message"] if required
      {
        description: description,
        content: {
          "application/json" => {
            schema: schema
          }
        }
      }
    end

    def open_api_components(options)
      Schema.auth_tables(options).each_with_object({}) do |(model, table), schemas|
        name = model.to_s.split(/[_-]/).map(&:capitalize).join
        schemas[name.to_sym] = schema_for_table(table)
      end
    end

    def schema_for_table(table)
      required = []
      properties = table[:fields].each_with_object({}) do |(field, attributes), result|
        result[field.to_sym] = field_schema(attributes)
        required << field if attributes[:required] && attributes[:input] != false && field != "id"
      end
      {type: "object", properties: properties, required: required}
    end

    def field_schema(attributes)
      type = case attributes[:type].to_s
      when "date" then "string"
      when "number" then "number"
      when "boolean" then "boolean"
      else "string"
      end
      schema = {type: type}
      schema[:format] = "date-time" if attributes[:type].to_s == "date"
      schema[:default] = attributes[:default_value].respond_to?(:call) ? "Generated at runtime" : attributes[:default_value] if attributes.key?(:default_value)
      schema[:readOnly] = true if attributes[:input] == false
      schema
    end

    def open_api_html(schema, config)
      nonce = config[:nonce] ? " nonce=\"#{config[:nonce]}\"" : ""
      <<~HTML
        <!doctype html>
        <html>
          <head>
            <title>Scalar API Reference</title>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1" />
          </head>
          <body>
            <script id="api-reference" type="application/json">#{JSON.generate(schema)}</script>
            <script#{nonce}>window.scalarTheme = "#{config[:theme]}";</script>
            <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"#{nonce}></script>
          </body>
        </html>
      HTML
    end
  end
end
