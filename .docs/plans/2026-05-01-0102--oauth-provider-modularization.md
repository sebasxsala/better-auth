# OAuth Provider Modularization

- [x] Read root and package-level agent instructions.
- [x] Inspect upstream `packages/oauth-provider/src` structure.
- [x] Split Ruby OAuth provider methods into files that mirror upstream responsibilities.
- [x] Keep behavior unchanged by moving method bodies without rewriting logic.
- [x] Run oauth-provider tests and formatting checks.
- [x] Update this plan with any Ruby-specific adaptations found during the refactor.

## Notes

- No package-level `AGENTS.md` exists under `packages/better_auth-oauth-provider`.
- The upstream package is already checked out and contains modular files such as `authorize.ts`, `metadata.ts`, `register.ts`, `oauthClient/`, `oauthConsent/`, `token.ts`, `introspect.ts`, `revoke.ts`, `userinfo.ts`, `logout.ts`, `schema.ts`, and `utils/index.ts`.
- Ruby adaptation: files reopen `BetterAuth::Plugins` and use `module_function` so the existing plugin builder can keep calling the same method names.
- Ruby adaptation: most endpoint/helper methods live on `BetterAuth::Plugins`, while `validate_issuer_url` remains under `BetterAuth::Plugins::OAuthProvider` to preserve existing call sites.
- Verification: `rbenv exec bundle exec standardrb` and `rbenv exec bundle exec rake test` pass for `packages/better_auth-oauth-provider`.
