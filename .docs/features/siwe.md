# Feature: SIWE Plugin

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/siwe/index.ts`, `upstream/packages/better-auth/src/plugins/siwe/schema.ts`, `upstream/packages/better-auth/src/plugins/siwe/siwe.test.ts`

## Summary

Adds Sign-In with Ethereum nonce and verification endpoints.

Status: Complete for Ruby server parity.

## Ruby Adaptation

- Exposed as `BetterAuth::Plugins.siwe`.
- Adds `/siwe/nonce` and `/siwe/verify`.
- Adds plugin table `walletAddress` with `userId`, `address`, `chainId`, `isPrimary`, and `createdAt`.
- Stores nonces in the core verification table as `siwe:<wallet-address>:<chain-id>`.
- Creates or reuses users by wallet address, supports one wallet on multiple chains, creates `siwe` account records, and sets session cookies.
- Supports `anonymous`, `email_domain_name`, `get_nonce`, `verify_message`, and `ens_lookup`; `verify_message` receives the message, signature, checksum address, chain ID, and upstream-equivalent CAIP-122/EIP-191 payload.
- Normalizes wallet addresses with EIP-55 checksum casing using the same Keccak-256 algorithm upstream uses.
- Merges custom `schema` field/model mappings without losing base wallet-address metadata.

## Key Differences

- Upstream delegates SIWE signature verification to `verifyMessage`; Ruby keeps that model as `verify_message`, so no Ethereum crypto dependency was added.
- Ruby implements Keccak-256 internally for SIWE checksum casing rather than adding an Ethereum dependency.

## Testing

```bash
cd packages/better_auth
rbenv exec bundle exec rake test TEST=test/better_auth/plugins/siwe_test.rb
```

Key test file:

- `packages/better_auth/test/better_auth/plugins/siwe_test.rb`
