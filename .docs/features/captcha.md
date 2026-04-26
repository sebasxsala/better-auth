# Feature: Captcha Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/captcha/index.ts`, `upstream/packages/better-auth/src/plugins/captcha/constants.ts`, `upstream/packages/better-auth/src/plugins/captcha/error-codes.ts`, `upstream/packages/better-auth/src/plugins/captcha/verify-handlers/*.ts`, `upstream/packages/better-auth/src/plugins/captcha/captcha.test.ts`

## Summary

Adds request-time CAPTCHA enforcement for configured auth endpoints.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.captcha`.
- Protects `/sign-up/email`, `/sign-in/email`, and `/request-password-reset` by default.
- Supports custom `endpoints`, `secret_key`, `site_verify_url_override`, `site_key`, `min_score`, and test/app `verifier`.
- Supports Cloudflare Turnstile, Google reCAPTCHA, hCaptcha, and CaptchaFox with upstream-compatible JSON/form request shapes.
- Uses stdlib `Net::HTTP`; tests use injected verifiers instead of real external services.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec ruby -Itest test/better_auth/plugins/captcha_test.rb
```
