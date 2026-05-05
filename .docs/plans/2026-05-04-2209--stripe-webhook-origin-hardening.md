# Stripe Webhook And Redirect Hardening Plan

**Goal:** Preserve raw Stripe webhook payloads for signature verification and reject untrusted Stripe redirect URLs.

**Upstream reference:** `upstream/packages/stripe` at `@better-auth/stripe@1.6.9`.

## Tasks

- [x] Add raw-body endpoint support in core routing.
- [x] Update the Stripe webhook route to verify signatures with the raw request body.
- [x] Add Stripe redirect URL trust validation for checkout, portal, cancel, and callback flows.
- [x] Update Stripe docs with trusted redirect URL requirements.
- [x] Run package and targeted core tests.

## Notes

- No gem version bump.
- Scope is limited to critical webhook verification and redirect hardening.
