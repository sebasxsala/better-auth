# frozen_string_literal: true

require_relative "../../../test_helper"

class OAuthProviderOauthClientEndpointsTest < Minitest::Test
  include OAuthProviderFlowHelpers

  def test_client_management_create_read_list_update_rotate_delete
    auth = build_auth(scopes: ["openid", "profile", "email", "offline_access", "read", "write"])
    cookie = sign_up_cookie(auth)
    client = create_client(auth, cookie, client_name: "Original Client")

    fetched = auth.api.get_o_auth_client(headers: {"cookie" => cookie}, query: {client_id: client[:client_id]})
    listed = auth.api.get_o_auth_clients(headers: {"cookie" => cookie})
    updated = auth.api.update_o_auth_client(headers: {"cookie" => cookie}, body: {client_id: client[:client_id], update: {client_name: "Updated Client"}})
    rotated = auth.api.rotate_o_auth_client_secret(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})
    deleted = auth.api.delete_o_auth_client(headers: {"cookie" => cookie}, body: {client_id: client[:client_id]})

    assert_equal "Original Client", fetched[:client_name]
    assert_includes listed.map { |item| item[:client_id] }, client[:client_id]
    assert_equal "Updated Client", updated[:client_name]
    refute_equal client[:client_secret], rotated[:client_secret]
    assert_equal({deleted: true}, deleted)
  end
end
