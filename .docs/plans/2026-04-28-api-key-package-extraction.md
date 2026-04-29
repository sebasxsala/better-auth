# API Key Package Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Extract the Ruby API key plugin into `better_auth-api-key`, matching upstream `@better-auth/api-key`.

**Architecture:** `better_auth` remains the framework-agnostic core gem and keeps only a compatibility shim for `BetterAuth::Plugins.api_key`. The external package owns the API key implementation, tests, docs, and package metadata while preserving the public Ruby plugin entrypoint.

**Tech Stack:** Ruby 3.2+, Rack 3, Minitest, StandardRB, existing BetterAuth plugin system, upstream `upstream/packages/api-key`.

---

## Tasks

- [x] Create `packages/better_auth-api-key` with gemspec, entrypoint, version, README, changelog, Rakefile, and test helper.
- [x] Move the API key implementation and Minitest coverage into the external package.
- [x] Replace the core API key implementation with a helpful external-package shim.
- [x] Add core shim coverage for missing `better_auth/api_key`.
- [x] Update workspace Gemfile, Rakefile, CI, release docs, README, and parity docs.
- [x] Run focused package/core verification.

## Ruby-Specific Decisions

- Keep the public API as `BetterAuth::Plugins.api_key`.
- Use `require "better_auth/api_key"` as the explicit external package entrypoint.
- Do not add runtime dependencies beyond `better_auth`; the plugin uses Ruby stdlib for JSON, randomness, and time handling.
- Preserve the existing Ruby implementation exactly during extraction; any further upstream parity changes should be handled in a follow-up plan.
