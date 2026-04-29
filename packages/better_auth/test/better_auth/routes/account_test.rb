# frozen_string_literal: true

require_relative "../../test_helper"

class BetterAuthRoutesAccountTest < Minitest::Test
  SECRET = "phase-five-secret-with-enough-entropy-123"

  def test_list_accounts_returns_current_user_accounts_with_scope_array
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "accounts@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: user_id, providerId: "github", accountId: "gh-1", scope: "repo,user")

    accounts = auth.api.list_accounts(headers: {"cookie" => cookie})

    github = accounts.find { |account| account["providerId"] == "github" }
    assert_equal ["repo", "user"], github["scopes"]
    refute github.key?("accessToken")
  end

  def test_unlink_account_removes_matching_account_but_not_last_account
    auth = build_auth(account: {account_linking: {allow_unlinking_all: false}})
    cookie = sign_up_cookie(auth, email: "unlink@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    auth.context.internal_adapter.create_account(userId: user_id, providerId: "github", accountId: "gh-1")

    assert_equal({status: true}, auth.api.unlink_account(headers: {"cookie" => cookie}, body: {providerId: "github"}))

    error = assert_raises(BetterAuth::APIError) do
      auth.api.unlink_account(headers: {"cookie" => cookie}, body: {providerId: "credential"})
    end
    assert_equal 400, error.status_code
    assert_equal BetterAuth::BASE_ERROR_CODES["FAILED_TO_UNLINK_LAST_ACCOUNT"], error.message
  end

  def test_get_access_token_and_refresh_token_use_configured_provider
    refreshed_at = Time.now + 3600
    provider = {
      id: "github",
      refresh_access_token: ->(_refresh_token) {
        {
          accessToken: "new-access",
          refreshToken: "new-refresh",
          accessTokenExpiresAt: refreshed_at,
          refreshTokenExpiresAt: refreshed_at + 3600,
          scopes: ["repo"],
          idToken: "new-id"
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "tokens@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-1",
      accessToken: "old-access",
      refreshToken: "old-refresh",
      accessTokenExpiresAt: Time.now - 60,
      scope: "user"
    )

    token_data = auth.api.get_access_token(headers: {"cookie" => cookie}, body: {providerId: "github"})
    assert_equal "new-access", token_data[:accessToken]
    assert_equal ["repo"], token_data[:scopes]

    refresh_data = auth.api.refresh_token(headers: {"cookie" => cookie}, body: {providerId: "github", accountId: account["id"]})
    assert_equal "new-refresh", refresh_data[:refreshToken]
    assert_equal "github", refresh_data[:providerId]
  end

  def test_account_info_calls_provider_user_info
    provider = {
      id: "github",
      get_user_info: ->(tokens) {
        {
          user: {id: "gh-1", email: "provider@example.com", name: "Provider User"},
          data: {accessToken: tokens[:accessToken]}
        }
      }
    }
    auth = build_auth(social_providers: {github: provider})
    cookie = sign_up_cookie(auth, email: "info@example.com")
    user_id = auth.api.get_session(headers: {"cookie" => cookie})[:user]["id"]
    account = auth.context.internal_adapter.create_account(
      userId: user_id,
      providerId: "github",
      accountId: "gh-1",
      accessToken: "access-token"
    )

    info = auth.api.account_info(headers: {"cookie" => cookie}, query: {accountId: account["id"]})

    assert_equal "provider@example.com", info[:user][:email]
    assert_equal "access-token", info[:data][:accessToken]
  end

  private

  def build_auth(options = {})
    email_and_password = {enabled: true}.merge(options.fetch(:email_and_password, {}))
    BetterAuth.auth({base_url: "http://localhost:3000", secret: SECRET, database: :memory}.merge(options).merge(email_and_password: email_and_password))
  end

  def sign_up_cookie(auth, email:)
    _status, headers, _body = auth.api.sign_up_email(
      body: {email: email, password: "password123", name: "Account User"},
      as_response: true
    )
    headers.fetch("set-cookie").lines.map { |line| line.split(";").first }.join("; ")
  end
end
