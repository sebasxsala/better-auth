# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-04-29

### Added

- Added upstream-parity social provider support, including provider-specific authorization, token, profile, refresh, and revocation behavior for the expanded provider set.
- Added OAuth/OIDC protocol hardening for authorization, callback, discovery, metadata, token, and userinfo flows.
- Added upstream v1.6.9 parity coverage for schema generation, adapter behavior, plugin hooks, session handling, and account/user route edge cases.

### Changed

- Extracted MongoDB adapter support behind the external `better_auth-mongo-adapter` shim while preserving compatibility for existing adapter configuration.
- Updated auth routes, router behavior, rate limiting, password and email-verification flows, and schema metadata to match upstream semantics more closely.

### Fixed

- Fixed social provider edge cases, magic-link expiration behavior, adapter value coercion, and callback/session handling across Rack integrations.

## [0.1.1] - 2026-03-22

### Fixed

- Fixed gemspec files list to use `Dir.glob` instead of `git ls-files` for better CI compatibility

### Added

- Initial project setup
- Basic gem structure
- StandardRB configuration
- Minitest for core testing
- RSpec for Rails adapter testing
- CI/CD workflows for GitHub Actions
