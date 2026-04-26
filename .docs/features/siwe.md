# Feature: SIWE Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/siwe/index.ts`, `upstream/packages/better-auth/src/plugins/siwe/schema.ts`, `upstream/packages/better-auth/src/plugins/siwe/siwe.test.ts`

## Summary

Adds Sign-In with Ethereum nonce and verification endpoints.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.siwe`.
- Adds `/siwe/nonce` and `/siwe/verify`.
- Adds plugin table `walletAddress` with `userId`, `address`, `chainId`, `isPrimary`, and `createdAt`.
- Stores nonces in the core verification table as `siwe:<wallet-address>:<chain-id>`.
- Creates or reuses users by wallet address, supports one wallet on multiple chains, creates `siwe` account records, and sets session cookies.
- Supports `anonymous`, `email_domain_name`, `get_nonce`, `verify_message`, and `ens_lookup`.

## Key Differences

- Upstream delegates SIWE signature verification to `verifyMessage`; Ruby keeps that model as `verify_message`, so no Ethereum crypto dependency was added.
- Wallet addresses are normalized to lowercase for deterministic lookup. Full EIP-55 checksum casing would require Keccak support; this remains a dependency decision if exact display checksum parity becomes necessary.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/siwe_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/siwe_test.rb`
