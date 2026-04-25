# frozen_string_literal: true

require "uri"

module BetterAuth
  class Context
    attr_reader :app_name,
      :base_url,
      :version,
      :options,
      :social_providers,
      :cookies,
      :adapter,
      :internal_adapter,
      :logger,
      :session_config,
      :rate_limit_config,
      :trusted_origins,
      :secret,
      :current_session,
      :new_session

    def initialize(configuration)
      @app_name = configuration.app_name
      @base_url = configuration.context_base_url
      @version = BetterAuth::VERSION
      @options = configuration
      @social_providers = configuration.social_providers
      @cookies = {}
      @adapter = configuration.database
      @internal_adapter = nil
      @logger = configuration.logger
      @session_config = configuration.session
      @rate_limit_config = configuration.rate_limit
      @trusted_origins = configuration.trusted_origins
      @secret = configuration.secret
      @current_session = nil
      @new_session = nil
    end

    def trusted_origin?(url, allow_relative_paths: false)
      trusted_origins.any? do |origin|
        Configuration.matches_origin_pattern?(url, origin, allow_relative_paths: allow_relative_paths)
      end
    end

    def set_new_session(session)
      @new_session = session
    end

    def prepare_for_request!(request)
      @base_url = inferred_base_url(request) if options.base_url.to_s.empty?
      @trusted_origins = current_trusted_origins(request)
    end

    private

    def inferred_base_url(request)
      origin = inferred_origin(request)
      path = options.base_path
      path.empty? ? origin : "#{origin}#{path}"
    end

    def inferred_origin(request)
      forwarded_host = request.get_header("HTTP_X_FORWARDED_HOST")
      forwarded_proto = request.get_header("HTTP_X_FORWARDED_PROTO")
      if options.advanced[:trusted_proxy_headers] && valid_forwarded?(forwarded_host, forwarded_proto)
        return "#{forwarded_proto}://#{forwarded_host}"
      end

      scheme = request.get_header("rack.url_scheme") || request.scheme
      host_header = request.get_header("HTTP_HOST")
      return "#{scheme}://#{host_header}" if host_header && !host_header.empty?

      host = request.get_header("SERVER_NAME") || request.host
      port = (request.get_header("SERVER_PORT") || request.port).to_i
      default_port = (scheme == "http" && port == 80) || (scheme == "https" && port == 443)
      default_port ? "#{scheme}://#{host}" : "#{scheme}://#{host}:#{port}"
    end

    def valid_forwarded?(host, proto)
      valid_proxy_proto?(proto.to_s) && valid_proxy_host?(host.to_s)
    end

    def valid_proxy_proto?(proto)
      %w[http https].include?(proto)
    end

    def valid_proxy_host?(host)
      return false if host.strip.empty?

      suspicious_patterns = [
        /\.\./,
        /\0/,
        /\s/,
        /\A[.]/,
        /[<>'"]/,
        /javascript:/i,
        /file:/i,
        /data:/i,
        %r{[/\\]}
      ]
      return false if suspicious_patterns.any? { |pattern| host.match?(pattern) }

      hostname = /\A[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?\z/
      ipv4 = /\A(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?\z/
      ipv6 = /\A\[[0-9a-fA-F:]+\](:[0-9]{1,5})?\z/
      localhost = /\Alocalhost(:[0-9]{1,5})?\z/i
      return false unless [hostname, ipv4, ipv6, localhost].any? { |pattern| host.match?(pattern) }

      valid_port?(host)
    end

    def valid_port?(host)
      port = host[/:(\d{1,5})\z/, 1]
      return true unless port

      port.to_i.between?(1, 65_535)
    end

    def current_trusted_origins(request)
      origins = []
      origins << Configuration.origin_for(URI.parse(base_url)) unless base_url.to_s.empty?
      origins.concat(options.trusted_origins)
      if options.trusted_origins_callback
        origins.concat(Array(options.trusted_origins_callback.call(request)).compact)
      end
      origins.concat(ENV.fetch("BETTER_AUTH_TRUSTED_ORIGINS", "").split(",").map(&:strip))
      origins.map(&:to_s).reject(&:empty?).uniq
    rescue URI::InvalidURIError
      options.trusted_origins
    end
  end
end
