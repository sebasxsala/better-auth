# frozen_string_literal: true

require "json"
require_relative "../../test_helper"

class BetterAuthPluginsOrganizationTest < Minitest::Test
  SECRET = "phase-ten-organization-secret-with-enough-entropy"

  def test_creates_lists_updates_activates_and_deletes_organizations
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "owner@example.com")

    created = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Acme Inc", slug: "acme", metadata: {plan: "pro"}}
    )

    assert_equal "Acme Inc", created.fetch("name")
    assert_equal "acme", created.fetch("slug")
    assert_equal({"plan" => "pro"}, created.fetch("metadata"))

    assert_equal false, auth.api.check_organization_slug(body: {slug: "acme"}).fetch(:available)
    assert_equal ["acme"], auth.api.list_organizations(headers: {"cookie" => cookie}).map { |org| org.fetch("slug") }

    updated = auth.api.update_organization(
      headers: {"cookie" => cookie},
      body: {organizationId: created.fetch("id"), data: {name: "Acme Labs", slug: "acme-labs"}}
    )
    assert_equal "Acme Labs", updated.fetch("name")
    assert_equal "acme-labs", updated.fetch("slug")

    active = auth.api.set_active_organization(
      headers: {"cookie" => cookie},
      body: {organizationId: created.fetch("id")},
      return_headers: true
    )
    assert_equal created.fetch("id"), active.fetch(:response).fetch("id")
    active_cookie = [cookie, cookie_header(active.fetch(:headers).fetch("set-cookie"))].join("; ")
    session = auth.api.get_session(headers: {"cookie" => active_cookie})
    assert_equal created.fetch("id"), session.fetch(:session).fetch("activeOrganizationId")

    deleted = auth.api.delete_organization(headers: {"cookie" => cookie}, body: {organizationId: created.fetch("id")})
    assert_equal({status: true}, deleted)
    assert_empty auth.api.list_organizations(headers: {"cookie" => cookie})
  end

  def test_invites_accepts_lists_and_updates_members
    auth = build_auth
    owner_cookie = sign_up_cookie(auth, email: "org-owner@example.com")
    member_cookie = sign_up_cookie(auth, email: "member@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Team Org", slug: "team-org"})

    invitation = auth.api.create_invitation(
      headers: {"cookie" => owner_cookie},
      body: {organizationId: organization.fetch("id"), email: "MEMBER@example.com", role: ["member", "admin"]}
    )
    assert_equal "member,admin", invitation.fetch("role")
    assert_equal "pending", invitation.fetch("status")

    accepted = auth.api.accept_invitation(headers: {"cookie" => member_cookie}, body: {invitationId: invitation.fetch("id")})
    assert_equal "accepted", accepted.fetch(:invitation).fetch("status")
    assert_equal "member,admin", accepted.fetch(:member).fetch("role")

    members = auth.api.list_members(headers: {"cookie" => owner_cookie}, query: {organizationId: organization.fetch("id")})
    assert_equal 2, members.fetch(:total)

    updated = auth.api.update_member_role(
      headers: {"cookie" => owner_cookie},
      body: {organizationId: organization.fetch("id"), memberId: accepted.fetch(:member).fetch("id"), role: "member"}
    )
    assert_equal "member", updated.fetch("role")

    removed = auth.api.remove_member(
      headers: {"cookie" => owner_cookie},
      body: {organizationId: organization.fetch("id"), memberId: accepted.fetch(:member).fetch("id")}
    )
    assert_equal({status: true}, removed)
  end

  def test_teams_and_dynamic_roles
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"]
    )
    auth = build_auth(plugins: [BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true}, ac: ac)])
    cookie = sign_up_cookie(auth, email: "teams@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Teams", slug: "teams"})

    team = auth.api.create_team(headers: {"cookie" => cookie}, body: {organizationId: organization.fetch("id"), name: "Engineering"})
    assert_equal "Engineering", team.fetch("name")
    assert_includes auth.api.list_organization_teams(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id")}).map { |entry| entry.fetch("id") }, team.fetch("id")

    role = auth.api.create_org_role(
      headers: {"cookie" => cookie},
      body: {organizationId: organization.fetch("id"), role: "billing", permission: {organization: ["update"], ac: ["read"]}}
    )
    assert_equal "billing", role.fetch("role")

    roles = auth.api.list_org_roles(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id")})
    assert_includes roles.map { |entry| entry.fetch("role") }, "billing"

    assert_equal true, auth.api.has_permission(
      headers: {"cookie" => cookie},
      body: {organizationId: organization.fetch("id"), permissions: {organization: ["delete"]}}
    ).fetch(:success)
  end

  def test_invokes_organization_hooks
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization(
          hooks: {
            before_create_organization: ->(data, _ctx) { calls << [:before_create, data[:organization][:slug]] },
            after_create_organization: ->(data, _ctx) { calls << [:after_create, data[:organization].fetch("slug")] }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "hooks@example.com")

    auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Hooks", slug: "hooks"})

    assert_equal [[:before_create, "hooks"], [:after_create, "hooks"]], calls
  end

  private

  def build_auth(options = {})
    BetterAuth.auth({
      secret: SECRET,
      database: :memory,
      plugins: [BetterAuth::Plugins.organization(teams: {enabled: true}, dynamic_access_control: {enabled: true})]
    }.merge(options))
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
