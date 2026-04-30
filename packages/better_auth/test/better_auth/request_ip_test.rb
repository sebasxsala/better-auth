# frozen_string_literal: true

require "rack/mock"
require_relative "../test_helper"

class BetterAuthRequestIPTest < Minitest::Test
  SECRET = "request-ip-secret-with-enough-entropy"

  def test_uses_configured_headers_in_order
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {
        ip_address: {
          ip_address_headers: ["x-client-ip", "x-forwarded-for"]
        }
      }
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_CLIENT_IP" => "203.0.113.7", "HTTP_X_FORWARDED_FOR" => "198.51.100.2"))

    assert_equal "203.0.113.7", BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_disable_ip_tracking_returns_nil
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {ip_address: {disable_ip_tracking: true}}
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "203.0.113.7"))

    assert_nil BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_masks_ipv6_addresses
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {ip_address: {ipv6_subnet: 64}}
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "2001:db8:abcd:1234:ffff::1"))

    assert_equal "2001:db8:abcd:1234::", BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_converts_ipv4_mapped_ipv6_to_ipv4
    config = BetterAuth::Configuration.new(secret: SECRET)
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "::ffff:192.0.2.1"))

    assert_equal "192.0.2.1", BetterAuth::RequestIP.client_ip(request, config)
  end

  def test_ipv6_subnet_does_not_affect_ipv4_addresses
    config = BetterAuth::Configuration.new(
      secret: SECRET,
      advanced: {ip_address: {ipv6_subnet: 64}}
    )
    request = Rack::Request.new(Rack::MockRequest.env_for("/", "HTTP_X_FORWARDED_FOR" => "192.168.1.1"))

    assert_equal "192.168.1.1", BetterAuth::RequestIP.client_ip(request, config)
  end
end
