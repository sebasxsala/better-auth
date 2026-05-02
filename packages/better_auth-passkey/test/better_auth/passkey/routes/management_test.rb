# frozen_string_literal: true

require_relative "../support"

class BetterAuthPasskeyRoutesManagementTest < Minitest::Test
  include BetterAuthPasskeyTestSupport

  def test_list_update_and_delete_are_scoped_to_current_user
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-management-route@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-management-route@example.com")
    first_user = auth.api.get_session(headers: {"cookie" => first_cookie})[:user]
    second_user = auth.api.get_session(headers: {"cookie" => second_cookie})[:user]
    first = create_passkey(auth, user_id: first_user.fetch("id"), name: "First")
    second = create_passkey(auth, user_id: second_user.fetch("id"), name: "Second")

    listed = auth.api.list_passkeys(headers: {"cookie" => first_cookie})
    updated = auth.api.update_passkey(headers: {"cookie" => first_cookie}, body: {id: first.fetch("id"), name: "Renamed"})
    unauthorized = assert_raises(BetterAuth::APIError) do
      auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: second.fetch("id")})
    end
    deleted = auth.api.delete_passkey(headers: {"cookie" => first_cookie}, body: {id: first.fetch("id")})

    assert_equal [first.fetch("id")], listed.map { |passkey| passkey.fetch("id") }
    assert_equal "Renamed", updated.fetch(:passkey).fetch("name")
    assert_equal 401, unauthorized.status_code
    assert_equal({status: true}, deleted)
  end

  def test_update_rejects_another_users_passkey_without_changing_name
    auth = build_auth
    first_cookie = sign_up_cookie(auth, email: "first-update-route@example.com")
    second_cookie = sign_up_cookie(auth, email: "second-update-route@example.com")
    second_user = auth.api.get_session(headers: {"cookie" => second_cookie})[:user]
    other_passkey = create_passkey(auth, user_id: second_user.fetch("id"), name: "Original", credential_id: "other-update-route")

    error = assert_raises(BetterAuth::APIError) do
      auth.api.update_passkey(headers: {"cookie" => first_cookie}, body: {id: other_passkey.fetch("id"), name: "Changed"})
    end

    assert_equal 401, error.status_code
    assert_equal BetterAuth::Plugins::PASSKEY_ERROR_CODES.fetch("YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"), error.message
    assert_equal "Original", auth.context.adapter.find_one(model: "passkey", where: [{field: "id", value: other_passkey.fetch("id")}]).fetch("name")
  end
end
