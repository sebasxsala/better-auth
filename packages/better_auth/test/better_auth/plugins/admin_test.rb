# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsAdminTest < Minitest::Test
  SECRET = "phase-ten-admin-secret-with-enough-entropy"

  def test_admin_manages_users_roles_bans_sessions_and_passwords
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    user = auth.api.get_session(headers: {"cookie" => user_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    users = auth.api.list_users(headers: {"cookie" => admin_cookie}, query: {searchValue: "user", searchField: "email"})
    assert_equal 1, users.fetch(:total)
    assert_equal "user@example.com", users.fetch(:users).first.fetch("email")

    created = auth.api.create_user(
      headers: {"cookie" => admin_cookie},
      body: {email: "created@example.com", password: "password123", name: "Created", role: ["user", "support"]}
    )
    assert_equal "user,support", created.fetch(:user).fetch("role")

    auth.api.set_role(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), role: "support"})
    assert_equal "support", auth.context.internal_adapter.find_user_by_id(user.fetch("id")).fetch("role")

    banned = auth.api.ban_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), banReason: "spam"})
    assert_equal true, banned.fetch("banned")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.sign_in_email(body: {email: "user@example.com", password: "password123"})
    end
    assert_equal 403, error.status_code

    auth.api.unban_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")})
    auth.api.set_user_password(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id"), newPassword: "newpassword123"})
    assert auth.api.sign_in_email(body: {email: "user@example.com", password: "newpassword123"}).fetch(:token)

    impersonated = auth.api.impersonate_user(headers: {"cookie" => admin_cookie}, body: {userId: user.fetch("id")})
    assert_equal admin.fetch("id"), impersonated.fetch(:session).fetch("impersonatedBy")

    stopped = auth.api.stop_impersonating(headers: {"cookie" => cookie_header(impersonated.fetch(:headers).fetch("set-cookie"))})
    assert_equal({status: true}, stopped)
  end

  def test_blocks_non_admin_and_checks_permissions
    auth = build_auth
    admin_cookie = sign_up_cookie(auth, email: "permissions-admin@example.com")
    user_cookie = sign_up_cookie(auth, email: "permissions-user@example.com")
    admin = auth.api.get_session(headers: {"cookie" => admin_cookie}).fetch(:user)
    auth.context.internal_adapter.update_user(admin.fetch("id"), role: "admin")

    denied = assert_raises(BetterAuth::APIError) do
      auth.api.list_users(headers: {"cookie" => user_cookie})
    end
    assert_equal 403, denied.status_code

    assert_equal true, auth.api.user_has_permission(
      headers: {"cookie" => admin_cookie},
      body: {permissions: {user: ["list"], session: ["revoke"]}}
    ).fetch(:success)
    assert_equal false, auth.api.user_has_permission(
      headers: {"cookie" => user_cookie},
      body: {permissions: {user: ["list"]}}
    ).fetch(:success)
  end

  private

  def build_auth
    BetterAuth.auth({
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.admin]
    })
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: email.split("@").first},
      as_response: true
    )
    cookie_header(headers.fetch("set-cookie"))
  end

  def cookie_header(set_cookie)
    set_cookie.to_s.lines.map { |line| line.split(";").first }.join("; ")
  end
end
