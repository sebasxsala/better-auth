# frozen_string_literal: true

module BetterAuth
  class APIError < Error
    STATUS_CODES = {
      "BAD_REQUEST" => 400,
      "UNAUTHORIZED" => 401,
      "FORBIDDEN" => 403,
      "NOT_FOUND" => 404,
      "METHOD_NOT_ALLOWED" => 405,
      "UNPROCESSABLE_ENTITY" => 422,
      "TOO_MANY_REQUESTS" => 429,
      "BAD_GATEWAY" => 502,
      "NOT_IMPLEMENTED" => 501,
      "FOUND" => 302,
      "INTERNAL_SERVER_ERROR" => 500
    }.freeze

    attr_reader :status, :status_code, :headers

    def initialize(status, message: nil, headers: {})
      @status = status.to_s.upcase
      @status_code = STATUS_CODES.fetch(@status, 500)
      @headers = normalize_headers(headers)
      super(message || default_message)
    end

    def to_h
      {
        code: status,
        message: message
      }
    end

    private

    def default_message
      status.split("_").map(&:capitalize).join(" ")
    end

    def normalize_headers(headers)
      headers.each_with_object({}) do |(key, value), result|
        result[key.to_s.downcase] = value
      end
    end
  end
end
