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
    assert_equal 1, created.fetch(:members).length

    assert_equal true, auth.api.check_organization_slug(body: {slug: "acme-open"}).fetch(:status)
    taken = assert_raises(BetterAuth::APIError) do
      auth.api.check_organization_slug(body: {slug: "acme"})
    end
    assert_equal 400, taken.status_code
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

  def test_create_organization_sets_active_and_supports_internal_user_id
    auth = build_auth
    cookie = sign_up_cookie(auth, email: "active-owner@example.com")
    owner = auth.api.get_session(headers: {"cookie" => cookie}).fetch(:user)

    created = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Active Org", slug: "active-org"},
      return_headers: true
    )
    created_cookie = [cookie, cookie_header(created.fetch(:headers).fetch("set-cookie"))].join("; ")
    session = auth.api.get_session(headers: {"cookie" => created_cookie})
    assert_equal created.fetch(:response).fetch("id"), session.fetch(:session).fetch("activeOrganizationId")
    assert created.fetch(:response).fetch(:members).any? { |member| member.fetch("userId") == owner.fetch("id") }

    internal = auth.api.create_organization(body: {name: "Internal Org", slug: "internal-org", userId: owner.fetch("id")})
    assert_equal "internal-org", internal.fetch("slug")
    assert internal.fetch(:members).any? { |member| member.fetch("userId") == owner.fetch("id") }

    kept = auth.api.create_organization(
      headers: {"cookie" => created_cookie},
      body: {name: "Kept Org", slug: "kept-org", keepCurrentActiveOrganization: true},
      return_headers: true
    )
    refute kept.fetch(:headers).key?("set-cookie")
    unchanged = auth.api.get_session(headers: {"cookie" => created_cookie})
    assert_equal created.fetch(:response).fetch("id"), unchanged.fetch(:session).fetch("activeOrganizationId")
  end

  def test_invitation_security_edges_and_limits
    auth = build_auth(plugins: [BetterAuth::Plugins.organization(invitation_limit: 1)])
    owner_cookie = sign_up_cookie(auth, email: "invite-owner@example.com")
    invitee_cookie = sign_up_cookie(auth, email: "invitee@example.com")
    other_cookie = sign_up_cookie(auth, email: "other-invitee@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Invites", slug: "invites"})

    invalid_email = assert_raises(BetterAuth::APIError) do
      auth.api.create_invitation(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), email: "bad-email", role: "member"})
    end
    assert_equal 400, invalid_email.status_code

    invitation = auth.api.create_invitation(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), email: "invitee@example.com", role: "member"})

    duplicate = assert_raises(BetterAuth::APIError) do
      auth.api.create_invitation(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), email: "INVITEE@example.com", role: "member"})
    end
    assert_equal 409, duplicate.status_code

    wrong_recipient = assert_raises(BetterAuth::APIError) do
      auth.api.accept_invitation(headers: {"cookie" => other_cookie}, body: {invitationId: invitation.fetch("id")})
    end
    assert_equal 403, wrong_recipient.status_code

    auth.context.adapter.update(model: "invitation", where: [{field: "id", value: invitation.fetch("id")}], update: {expiresAt: Time.now - 60})
    expired = assert_raises(BetterAuth::APIError) do
      auth.api.accept_invitation(headers: {"cookie" => invitee_cookie}, body: {invitationId: invitation.fetch("id")})
    end
    assert_equal 400, expired.status_code
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
    assert_equal true, role.fetch(:success)
    assert_equal "billing", role.fetch(:roleData).fetch("role")

    roles = auth.api.list_org_roles(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id")})
    assert_includes roles.map { |entry| entry.fetch("role") }, "billing"

    assert_equal true, auth.api.has_permission(
      headers: {"cookie" => cookie},
      body: {organizationId: organization.fetch("id"), permissions: {organization: ["delete"]}}
    ).fetch(:success)
  end

  def test_team_limits_membership_checks_and_active_team_clear
    auth = build_auth(plugins: [BetterAuth::Plugins.organization(teams: {enabled: true, maximum_teams: 1, maximum_members_per_team: 1, default_team: {enabled: false}})])
    owner_cookie = sign_up_cookie(auth, email: "team-limit-owner@example.com")
    other_cookie = sign_up_cookie(auth, email: "team-limit-other@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Team Limit", slug: "team-limit"})
    team = auth.api.create_team(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), name: "One"})

    too_many = assert_raises(BetterAuth::APIError) do
      auth.api.create_team(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), name: "Two"})
    end
    assert_equal 403, too_many.status_code

    not_member = assert_raises(BetterAuth::APIError) do
      auth.api.set_active_team(headers: {"cookie" => other_cookie}, body: {teamId: team.fetch("id")})
    end
    assert_equal 403, not_member.status_code

    cleared = auth.api.set_active_team(headers: {"cookie" => owner_cookie}, body: {teamId: nil}, return_headers: true)
    cleared_cookie = [owner_cookie, cookie_header(cleared.fetch(:headers).fetch("set-cookie"))].join("; ")
    assert_nil auth.api.get_session(headers: {"cookie" => cleared_cookie}).fetch(:session)["activeTeamId"]
  end

  def test_dynamic_access_control_rejects_invalid_and_assigned_roles
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      project: ["create", "read", "update", "delete"]
    )
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization(
          dynamic_access_control: {enabled: true},
          ac: ac,
          roles: {
            owner: ac.new_role(organization: ["update", "delete"], member: ["create", "update", "delete"], invitation: ["create", "cancel"], team: ["create", "update", "delete"], ac: ["create", "read", "update", "delete"], project: ["create", "read", "update", "delete"]),
            member: ac.new_role(ac: ["read"])
          },
          schema: {
            organizationRole: {
              additionalFields: {
                color: {type: "string", required: false}
              }
            }
          }
        )
      ]
    )
    owner_cookie = sign_up_cookie(auth, email: "dac-owner@example.com")
    member_cookie = sign_up_cookie(auth, email: "dac-member@example.com")
    member_user = auth.api.get_session(headers: {"cookie" => member_cookie})[:user]
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "DAC", slug: "dac"})

    invalid = assert_raises(BetterAuth::APIError) do
      auth.api.create_org_role(
        headers: {"cookie" => owner_cookie},
        body: {organizationId: organization.fetch("id"), role: "billing", permission: {billing: ["read"]}}
      )
    end
    assert_equal 400, invalid.status_code
    assert_equal BetterAuth::Plugins::ORGANIZATION_ERROR_CODES.fetch("INVALID_RESOURCE"), invalid.message

    role = auth.api.create_org_role(
      headers: {"cookie" => owner_cookie},
      body: {organizationId: organization.fetch("id"), role: "project-reader", permission: {project: ["read"]}, additionalFields: {color: "#000000"}}
    )
    assert_equal true, role.fetch(:success)
    assert_equal({"project" => ["read"]}, role.fetch(:roleData).fetch("permission"))
    assert_equal "#000000", role.fetch(:roleData).fetch("color")

    auth.api.add_member(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), userId: member_user.fetch("id"), role: "project-reader"})

    assigned = assert_raises(BetterAuth::APIError) do
      auth.api.delete_org_role(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), roleName: "project-reader"})
    end
    assert_equal 400, assigned.status_code
    assert_equal BetterAuth::Plugins::ORGANIZATION_ERROR_CODES.fetch("ROLE_IS_ASSIGNED_TO_MEMBERS"), assigned.message
  end

  def test_dynamic_access_control_merges_database_permissions_with_builtin_roles
    ac = BetterAuth::Plugins.create_access_control(
      organization: ["update", "delete"],
      member: ["create", "update", "delete"],
      invitation: ["create", "cancel"],
      team: ["create", "update", "delete"],
      ac: ["create", "read", "update", "delete"],
      project: ["read"]
    )
    auth = build_auth(plugins: [BetterAuth::Plugins.organization(dynamic_access_control: {enabled: true}, ac: ac)])
    cookie = sign_up_cookie(auth, email: "merge-owner@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => cookie}, body: {name: "Merge", slug: "merge"})

    auth.context.adapter.create(model: "organizationRole", data: {organizationId: organization.fetch("id"), role: "owner", permission: JSON.generate(project: ["read"])})

    assert_equal true, auth.api.has_permission(
      headers: {"cookie" => cookie},
      body: {organizationId: organization.fetch("id"), permissions: {organization: ["delete"], project: ["read"]}}
    ).fetch(:success)
  end

  def test_additional_fields_and_organization_hooks
    calls = []
    auth = build_auth(
      plugins: [
        BetterAuth::Plugins.organization(
          teams: {enabled: true},
          organization_hooks: {
            before_create_organization: lambda { |data, _ctx|
              calls << [:before_create_org, data[:organization][:slug]]
              {data: {logo: "https://cdn.example/logo.png"}}
            },
            after_create_organization: ->(data, _ctx) { calls << [:after_create_org, data[:organization].fetch("slug")] },
            before_add_member: lambda { |data, _ctx|
              calls << [:before_add_member, data[:member][:role]]
              {data: {role: "admin", title: "Founder"}}
            },
            after_add_member: ->(data, _ctx) { calls << [:after_add_member, data[:member].fetch("role")] },
            before_create_team: lambda { |data, _ctx|
              calls << [:before_create_team, data[:team][:name]]
              {data: {name: "Founding Team", code: "founders"}}
            },
            after_create_team: ->(data, _ctx) { calls << [:after_create_team, data[:team].fetch("name")] }
          },
          schema: {
            organization: {
              additionalFields: {
                publicCode: {type: "string", required: false},
                secretCode: {type: "string", required: false, returned: false}
              }
            },
            member: {
              additionalFields: {
                title: {type: "string", required: false}
              }
            },
            team: {
              additionalFields: {
                code: {type: "string", required: false}
              }
            }
          }
        )
      ]
    )
    cookie = sign_up_cookie(auth, email: "additional@example.com")

    organization = auth.api.create_organization(
      headers: {"cookie" => cookie},
      body: {name: "Additional", slug: "additional", additionalFields: {publicCode: "public", secretCode: "secret"}}
    )

    assert_equal "https://cdn.example/logo.png", organization.fetch("logo")
    assert_equal "public", organization.fetch("publicCode")
    refute organization.key?("secretCode")

    full = auth.api.get_full_organization(headers: {"cookie" => cookie}, query: {organizationId: organization.fetch("id")})
    assert_equal "admin", full.fetch(:members).first.fetch("role")
    assert_equal "Founder", full.fetch(:members).first.fetch("title")
    assert_equal "Founding Team", full.fetch(:teams).first.fetch("name")
    assert_equal "founders", full.fetch(:teams).first.fetch("code")
    assert_equal [
      [:before_create_org, "additional"],
      [:before_add_member, "owner"],
      [:after_add_member, "admin"],
      [:before_create_team, "Additional"],
      [:after_create_team, "Founding Team"],
      [:after_create_org, "additional"]
    ], calls
  end

  def test_multi_team_invitations_join_all_teams
    auth = build_auth
    owner_cookie = sign_up_cookie(auth, email: "multi-team-owner@example.com")
    invitee_cookie = sign_up_cookie(auth, email: "multi-team-invitee@example.com")
    organization = auth.api.create_organization(headers: {"cookie" => owner_cookie}, body: {name: "Multi Team", slug: "multi-team"})
    engineering = auth.api.create_team(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), name: "Engineering"})
    support = auth.api.create_team(headers: {"cookie" => owner_cookie}, body: {organizationId: organization.fetch("id"), name: "Support"})

    invitation = auth.api.create_invitation(
      headers: {"cookie" => owner_cookie},
      body: {organizationId: organization.fetch("id"), email: "multi-team-invitee@example.com", role: "member", teamId: [engineering.fetch("id"), support.fetch("id")]}
    )
    assert_equal [engineering.fetch("id"), support.fetch("id")].join(","), invitation.fetch("teamId")

    auth.api.accept_invitation(headers: {"cookie" => invitee_cookie}, body: {invitationId: invitation.fetch("id")})
    team_ids = auth.api.list_user_teams(headers: {"cookie" => invitee_cookie}).map { |team| team.fetch("id") }

    assert_includes team_ids, engineering.fetch("id")
    assert_includes team_ids, support.fetch("id")
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
