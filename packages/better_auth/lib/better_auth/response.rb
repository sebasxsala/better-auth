# frozen_string_literal: true

require "json"

module BetterAuth
  class Response
    attr_reader :status, :headers, :body

    def initialize(status:, headers:, body:)
      @status = status
      @headers = headers
      @body = body
    end

    def self.from_rack(tuple)
      status, headers, body = tuple
      new(status: status, headers: headers, body: body)
    end

    def to_a
      [status, headers, body]
    end

    alias_method :to_ary, :to_a

    def each(&block)
      to_a.each(&block)
    end

    def [](index)
      to_a[index]
    end

    def first
      status
    end

    def json(**options)
      JSON.parse(body.join, **options)
    end
  end
end
