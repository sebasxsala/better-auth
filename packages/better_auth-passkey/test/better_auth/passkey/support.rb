# frozen_string_literal: true

require_relative "../../test_helper"

module BetterAuthPasskeyTestSupport
  SECRET = "phase-eight-secret-with-enough-entropy-123"
  ORIGIN = "http://localhost:3000"

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({
      base_url: ORIGIN,
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.passkey]
    }.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Passkey User"},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def create_passkey(auth, user_id:, name:, credential_id: "#{name}-credential", transports: "internal", aaguid: nil)
    auth.context.adapter.create(
      model: "passkey",
      data: {
        userId: user_id,
        name: name,
        publicKey: "mock-public-key",
        credentialID: credential_id,
        counter: 0,
        deviceType: "singleDevice",
        backedUp: false,
        transports: transports,
        createdAt: Time.now,
        aaguid: aaguid
      }
    )
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
