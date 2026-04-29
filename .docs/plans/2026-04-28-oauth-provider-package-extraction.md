# OAuth Provider Package Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Extract the Ruby OAuth provider plugin into `better_auth-oauth-provider`, matching upstream `@better-auth/oauth-provider`.

**Architecture:** Keep `OAuthProtocol` in core because `oidc_provider`, `mcp`, and `device_authorization` use it. Move only the public `BetterAuth::Plugins.oauth_provider` implementation and tests into the external package. Core keeps a compatibility shim that loads `better_auth/oauth_provider` when installed and raises a helpful error otherwise.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, existing BetterAuth plugin system, upstream `upstream/packages/oauth-provider`.

---

## Tasks

- [x] Create `packages/better_auth-oauth-provider` skeleton.
- [x] Move OAuth provider implementation and tests from core to the new package.
- [x] Replace core implementation with a shim and add shim tests.
- [x] Make OAuth provider schema self-contained instead of borrowing `oidc_provider_schema`.
- [x] Update docs and parity matrix.
- [x] Fix the existing MongoDB StandardRB style issue.
- [x] Validate core, SSO, SCIM, SAML, and OAuth provider package tests/lint.
