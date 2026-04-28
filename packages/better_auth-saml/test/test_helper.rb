# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "minitest/autorun"

ENV["ruby-saml/testing"] = "true"

begin
  require "better_auth/saml"
rescue LoadError
  warn "Skipping better_auth-saml tests because ruby-saml is not installed"
end
