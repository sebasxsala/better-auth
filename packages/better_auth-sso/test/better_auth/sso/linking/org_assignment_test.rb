# frozen_string_literal: true

require_relative "../../../test_helper"

class BetterAuthSSOLinkingOrgAssignmentTest < Minitest::Test
  ContextWrapper = Struct.new(:context)
  Context = Struct.new(:adapter, :options)
  Options = Struct.new(:plugins)
  Plugin = Struct.new(:id)

  def test_does_not_assign_user_when_provider_domain_is_unverified
    ctx = build_context(
      providers: [provider(domainVerified: false)],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_empty ctx.context.adapter.members
  end

  def test_assigns_user_when_provider_domain_is_verified
    ctx = build_context(
      providers: [provider(domainVerified: true, organizationId: "org-1")],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_equal 1, ctx.context.adapter.members.length
    assert_equal "org-1", ctx.context.adapter.members.first.fetch("organizationId")
    assert_equal "member", ctx.context.adapter.members.first.fetch("role")
  end

  def test_assign_from_provider_uses_default_role
    ctx = build_context(providers: [], organizations: [organization])

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_from_provider(
      ctx,
      user: user,
      profile: normalized_profile,
      provider: provider(organizationId: "org-1"),
      provisioning_options: {default_role: "admin"}
    )

    assert_equal 1, ctx.context.adapter.members.length
    assert_equal "org-1", ctx.context.adapter.members.first.fetch("organizationId")
    assert_equal "admin", ctx.context.adapter.members.first.fetch("role")
  end

  def test_assign_from_provider_uses_get_role_with_profile_raw_attributes_and_token
    ctx = build_context(providers: [], organizations: [organization])
    calls = []
    get_role = lambda do |data|
      calls << data
      "owner"
    end

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_from_provider(
      ctx,
      user: user,
      profile: normalized_profile(raw_attributes: {"groups" => ["owners"]}),
      provider: provider(organizationId: "org-1"),
      token: {"access_token" => "token-1"},
      provisioning_options: {get_role: get_role}
    )

    assert_equal "owner", ctx.context.adapter.members.first.fetch("role")
    assert_equal "user-1", calls.first.fetch(:user).fetch("id")
    assert_equal({"groups" => ["owners"]}, calls.first.fetch(:userInfo))
    assert_equal({"access_token" => "token-1"}, calls.first.fetch(:token))
    assert_equal "org-1", calls.first.fetch(:provider).fetch("organizationId")
  end

  def test_assign_from_provider_does_not_assign_when_provisioning_disabled
    ctx = build_context(providers: [], organizations: [organization])

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_from_provider(
      ctx,
      user: user,
      profile: normalized_profile,
      provider: provider(organizationId: "org-1"),
      provisioning_options: {disabled: true}
    )

    assert_empty ctx.context.adapter.members
  end

  def test_assign_from_provider_does_not_assign_without_organization_plugin
    ctx = build_context(providers: [], organizations: [organization], plugins: [])

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_from_provider(
      ctx,
      user: user,
      profile: normalized_profile,
      provider: provider(organizationId: "org-1")
    )

    assert_empty ctx.context.adapter.members
  end

  def test_does_not_assign_user_when_email_domain_does_not_match_any_provider
    ctx = build_context(
      providers: [provider(domainVerified: true)],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user(email: "alice@other-domain.com"), config: {domain_verification: {enabled: true}})

    assert_empty ctx.context.adapter.members
  end

  def test_does_not_assign_user_when_provider_has_no_organization_id
    ctx = build_context(providers: [provider(domainVerified: true, organizationId: nil)])

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_empty ctx.context.adapter.members
  end

  def test_does_not_assign_user_when_domain_verified_field_is_missing_and_verification_enabled
    ctx = build_context(
      providers: [provider(domainVerified: nil, organizationId: "org-1").tap { |entry| entry.delete("domainVerified") }],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_empty ctx.context.adapter.members
  end

  def test_assigns_user_when_verification_is_disabled
    ctx = build_context(
      providers: [provider(domainVerified: false, organizationId: "org-1")],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: false}})

    assert_equal 1, ctx.context.adapter.members.length
    assert_equal "org-1", ctx.context.adapter.members.first.fetch("organizationId")
  end

  def test_does_not_assign_user_when_already_member_of_org
    existing_member = {
      "id" => "member-1",
      "organizationId" => "org-1",
      "userId" => "user-1",
      "role" => "admin",
      "createdAt" => Time.now
    }
    ctx = build_context(
      providers: [provider(domainVerified: true, organizationId: "org-1")],
      members: [existing_member],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_equal [existing_member], ctx.context.adapter.members
  end

  def test_only_uses_verified_provider_when_multiple_providers_claim_same_domain
    ctx = build_context(
      providers: [
        provider(id: "attacker-provider", providerId: "attacker-provider", issuer: "https://attacker.example.com", domainVerified: false, organizationId: "attacker-org"),
        provider(id: "legit-provider", providerId: "legit-provider", domainVerified: true, organizationId: "legit-org")
      ],
      organizations: [
        organization(id: "attacker-org", name: "Attacker Org", slug: "attacker-org"),
        organization(id: "legit-org", name: "Legit Org", slug: "legit-org")
      ]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(ctx, user: user, config: {domain_verification: {enabled: true}})

    assert_equal 1, ctx.context.adapter.members.length
    assert_equal "legit-org", ctx.context.adapter.members.first.fetch("organizationId")
  end

  def test_assign_by_domain_uses_default_role_and_fast_exact_domain_lookup
    ctx = build_context(
      providers: [provider(domain: "example.com", domainVerified: true, organizationId: "org-1")],
      organizations: [organization]
    )

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(
      ctx,
      user: user,
      provisioning_options: {default_role: "admin"},
      domain_verification: {enabled: true}
    )

    assert_equal "admin", ctx.context.adapter.members.first.fetch("role")
    assert_includes ctx.context.adapter.find_one_calls, [
      "ssoProvider",
      [{field: "domain", value: "example.com"}, {field: "domainVerified", value: true}]
    ]
  end

  def test_assign_by_domain_uses_get_role_with_empty_user_info
    ctx = build_context(
      providers: [provider(domain: "example.com", domainVerified: true, organizationId: "org-1")],
      organizations: [organization]
    )
    calls = []

    BetterAuth::SSO::Linking::OrgAssignment.assign_organization_by_domain(
      ctx,
      user: user,
      provisioning_options: {
        get_role: lambda do |data|
          calls << data
          "viewer"
        end
      },
      domain_verification: {enabled: true}
    )

    assert_equal "viewer", ctx.context.adapter.members.first.fetch("role")
    assert_equal({}, calls.first.fetch(:userInfo))
    assert_equal "org-1", calls.first.fetch(:provider).fetch("organizationId")
  end

  private

  def build_context(providers: [], members: [], organizations: [], plugins: [Plugin.new("organization")])
    adapter = FakeAdapter.new(providers: providers, members: members, organizations: organizations)
    ContextWrapper.new(Context.new(adapter, Options.new(plugins)))
  end

  def user(overrides = {})
    {
      "id" => "user-1",
      "email" => "alice@example.com",
      "name" => "Alice",
      "emailVerified" => true,
      "createdAt" => Time.now,
      "updatedAt" => Time.now
    }.merge(overrides.transform_keys(&:to_s))
  end

  def organization(overrides = {})
    {
      "id" => "org-1",
      "name" => "Test Org",
      "slug" => "test-org",
      "createdAt" => Time.now
    }.merge(overrides.transform_keys(&:to_s))
  end

  def provider(overrides = {})
    {
      "id" => "provider-1",
      "providerId" => "test-provider",
      "issuer" => "https://idp.example.com",
      "domain" => "example.com",
      "domainVerified" => false,
      "organizationId" => "org-1",
      "userId" => "user-1"
    }.merge(overrides.transform_keys(&:to_s))
  end

  def normalized_profile(overrides = {})
    {
      provider_type: "saml",
      provider_id: "test-provider",
      account_id: "account-1",
      email: "alice@example.com",
      email_verified: true,
      raw_attributes: {}
    }.merge(overrides)
  end

  class FakeAdapter
    attr_reader :providers, :members, :organizations, :find_one_calls

    def initialize(providers:, members:, organizations:)
      @providers = providers
      @members = members
      @organizations = organizations
      @find_one_calls = []
    end

    def find_many(model:, **)
      case model
      when "ssoProvider"
        providers
      when "member"
        members
      when "organization"
        organizations
      else
        []
      end
    end

    def find_one(model:, where:, **)
      find_one_calls << [model, where]
      find_many(model: model).find do |record|
        where.all? { |condition| record[condition.fetch(:field)] == condition.fetch(:value) }
      end
    end

    def create(model:, data:, **)
      case model
      when "member"
        members << data.transform_keys(&:to_s)
        members.last
      else
        data.transform_keys(&:to_s)
      end
    end
  end
end
