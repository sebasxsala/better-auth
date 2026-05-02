# frozen_string_literal: true

require "openssl"
require_relative "../../test_helper"

class BetterAuthSSOUtilsTest < Minitest::Test
  def test_domain_matches_matches_exact_and_subdomain
    assert BetterAuth::SSO::Utils.domain_matches?("company.com", "company.com, other.com")
    assert BetterAuth::SSO::Utils.domain_matches?("hr.company.com", "company.com, other.com")
    refute BetterAuth::SSO::Utils.domain_matches?("notcompany.com", "company.com, other.com")
  end

  def test_validate_email_domain_matches_single_domain_exactly
    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", "company.com")
  end

  def test_validate_email_domain_matches_single_domain_subdomains
    assert BetterAuth::SSO::Utils.validate_email_domain("user@hr.company.com", "company.com")
    assert BetterAuth::SSO::Utils.validate_email_domain("user@dept.hr.company.com", "company.com")
  end

  def test_validate_email_domain_rejects_different_domain
    refute BetterAuth::SSO::Utils.validate_email_domain("user@other.com", "company.com")
  end

  def test_validate_email_domain_rejects_suffix_that_is_not_subdomain
    refute BetterAuth::SSO::Utils.validate_email_domain("user@notcompany.com", "company.com")
  end

  def test_validate_email_domain_is_case_insensitive
    assert BetterAuth::SSO::Utils.validate_email_domain("USER@COMPANY.COM", "company.com")
    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", "COMPANY.COM")
  end

  def test_validate_email_domain_matches_any_comma_separated_domain
    domains = "company.com,subsidiary.com,acquired-company.com"

    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@subsidiary.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@acquired-company.com", domains)
  end

  def test_validate_email_domain_matches_subdomains_for_any_domain
    domains = "company.com,subsidiary.com"

    assert BetterAuth::SSO::Utils.validate_email_domain("user@hr.company.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@dept.subsidiary.com", domains)
  end

  def test_validate_email_domain_rejects_when_no_domain_matches
    domains = "company.com,subsidiary.com,acquired-company.com"

    refute BetterAuth::SSO::Utils.validate_email_domain("user@other.com", domains)
    refute BetterAuth::SSO::Utils.validate_email_domain("user@notcompany.com", domains)
  end

  def test_validate_email_domain_handles_whitespace_in_domain_list
    domains = "company.com, subsidiary.com , acquired-company.com"

    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@subsidiary.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@acquired-company.com", domains)
  end

  def test_validate_email_domain_handles_empty_domains_in_list
    domains = "company.com,,subsidiary.com"

    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("user@subsidiary.com", domains)
  end

  def test_validate_email_domain_is_case_insensitive_for_multiple_domains
    domains = "Company.COM,SUBSIDIARY.com"

    assert BetterAuth::SSO::Utils.validate_email_domain("user@company.com", domains)
    assert BetterAuth::SSO::Utils.validate_email_domain("USER@SUBSIDIARY.COM", domains)
  end

  def test_validate_email_domain_returns_false_for_empty_email
    refute BetterAuth::SSO::Utils.validate_email_domain("", "company.com")
  end

  def test_validate_email_domain_returns_false_for_empty_domain
    refute BetterAuth::SSO::Utils.validate_email_domain("user@company.com", "")
  end

  def test_validate_email_domain_returns_false_for_email_without_at
    refute BetterAuth::SSO::Utils.validate_email_domain("usercompany.com", "company.com")
  end

  def test_validate_email_domain_returns_false_for_whitespace_only_domain_list
    refute BetterAuth::SSO::Utils.validate_email_domain("user@company.com", ", ,")
  end

  def test_hostname_from_domain_extracts_bare_domain
    assert_equal "github.com", BetterAuth::SSO::Utils.hostname_from_domain("github.com")
  end

  def test_hostname_from_domain_extracts_full_url
    assert_equal "github.com", BetterAuth::SSO::Utils.hostname_from_domain("https://github.com")
  end

  def test_hostname_from_domain_extracts_url_with_port
    assert_equal "github.com", BetterAuth::SSO::Utils.hostname_from_domain("https://github.com:8081")
  end

  def test_hostname_from_domain_extracts_subdomain
    assert_equal "auth.github.com", BetterAuth::SSO::Utils.hostname_from_domain("auth.github.com")
  end

  def test_hostname_from_domain_extracts_url_with_path
    assert_equal "github.com", BetterAuth::SSO::Utils.hostname_from_domain("https://github.com/path/to/resource")
  end

  def test_hostname_from_domain_returns_nil_for_empty_string
    assert_nil BetterAuth::SSO::Utils.hostname_from_domain("")
  end

  def test_safe_json_parse_returns_object_as_is
    value = {"a" => 1, "nested" => {"b" => 2}}

    assert_same value, BetterAuth::SSO::Utils.safe_json_parse(value)
  end

  def test_safe_json_parse_parses_stringified_json
    assert_equal(
      {"a" => 1, "nested" => {"b" => 2}},
      BetterAuth::SSO::Utils.safe_json_parse('{"a":1,"nested":{"b":2}}')
    )
  end

  def test_safe_json_parse_returns_nil_for_nil_and_blank
    assert_nil BetterAuth::SSO::Utils.safe_json_parse(nil)
    assert_nil BetterAuth::SSO::Utils.safe_json_parse("")
  end

  def test_safe_json_parse_raises_for_invalid_json
    error = assert_raises(BetterAuth::Error) do
      BetterAuth::SSO::Utils.safe_json_parse("not valid json")
    end

    assert_match(/Failed to parse JSON/, error.message)
  end

  def test_safe_json_parse_handles_empty_object_json
    assert_equal({}, BetterAuth::SSO::Utils.safe_json_parse("{}"))
  end

  def test_parse_certificate_accepts_pem_and_raw_base64_certificates
    cert = test_certificate
    pem = cert.to_pem
    raw = pem.lines.reject { |line| line.include?("CERTIFICATE") }.join.delete("\n")

    pem_info = BetterAuth::SSO::Utils.parse_certificate(pem)
    raw_info = BetterAuth::SSO::Utils.parse_certificate(raw)

    assert_equal pem_info, raw_info
    assert_match(/\A([A-F0-9]{2}:){31}[A-F0-9]{2}\z/, pem_info.fetch(:fingerprint_sha256))
    assert_equal "RSA", pem_info.fetch(:public_key_algorithm)
    assert pem_info.fetch(:not_before)
    assert pem_info.fetch(:not_after)
  end

  def test_mask_client_id_matches_upstream_visibility
    assert_equal "****", BetterAuth::SSO::Utils.mask_client_id("abc")
    assert_equal "****", BetterAuth::SSO::Utils.mask_client_id("abcd")
    assert_equal "****7890", BetterAuth::SSO::Utils.mask_client_id("client-1234567890")
  end

  private

  def test_certificate
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse("/CN=idp.example.com")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.utc(2026, 1, 1)
    cert.not_after = Time.utc(2027, 1, 1)
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    cert
  end
end
