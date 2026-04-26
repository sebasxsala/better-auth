# frozen_string_literal: true

module BetterAuth
  module Routes
    def self.ok
      Endpoint.new(
        path: "/ok",
        method: "GET",
        metadata: {hide: true}
      ) do |ctx|
        ctx.json({ok: true})
      end
    end
  end
end
