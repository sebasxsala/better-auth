# frozen_string_literal: true

require "ipaddr"

module BetterAuth
  module RequestIP
    LOCALHOST_IP = "127.0.0.1"

    module_function

    def client_ip(request, options)
      ip_options = options.advanced[:ip_address] || {}
      return nil if ip_options[:disable_ip_tracking]

      Array(ip_options[:ip_address_headers] || ["x-forwarded-for"]).each do |header|
        value = header_value(request, header)
        next unless value.is_a?(String)

        ip = value.split(",").first.to_s.strip
        return normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)
      end

      ip = fallback_ip(request)
      return normalize_ip(ip, ipv6_subnet: ip_options[:ipv6_subnet]) if valid_ip?(ip)

      LOCALHOST_IP if test_or_development?
    end

    def header_value(request, header)
      return request.get_header(rack_header_name(header)) if request.respond_to?(:get_header)
      return request.headers[header.to_s.downcase] if request.respond_to?(:headers)
      return request[header.to_s.downcase] || request[header.to_s] || request[header.to_sym] if request.is_a?(Hash)

      nil
    end

    def fallback_ip(request)
      return request.ip.to_s if request.respond_to?(:ip)

      nil
    end

    def rack_header_name(header)
      "HTTP_#{header.to_s.upcase.tr("-", "_")}"
    end

    def valid_ip?(ip)
      return false if ip.to_s.empty? || ip.to_s.match?(/\s/)

      IPAddr.new(ip)
      true
    rescue ArgumentError
      false
    end

    def normalize_ip(ip, ipv6_subnet: nil)
      address = IPAddr.new(ip)
      return address.native.to_s if address.respond_to?(:ipv4_mapped?) && address.ipv4_mapped?
      return address.to_s if address.ipv4?

      address.mask((ipv6_subnet || 64).to_i).to_s
    end

    def test_or_development?
      ["test", "development"].include?(ENV["RACK_ENV"]) ||
        ["test", "development"].include?(ENV["RAILS_ENV"]) ||
        ["test", "development"].include?(ENV["APP_ENV"])
    end
  end
end
