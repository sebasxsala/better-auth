# Releasing

This document describes the release process for Better Auth Ruby gems.

## Version Branches

| Branch | Purpose |
|--------|---------|
| `canary` | Active development. All PRs merge here first. |
| `main` | Stable releases. Merges from `canary` when ready. |
| `v0.x` | Latest of the 0.x release line (current). |
| `v1.0.x`, `v1.1.x`, ... | Future version branches, created at release time. |

**Rules:**
- Major and minor versions get their own branch (`v1.0.x`, `v1.1.x`, `v2.0.x`)
- The `.x` suffix means "latest patch of this version"
- Patch versions do not get their own branch

## Release Process

### 1. Prepare the Release

Ensure `canary` is stable and all CI checks pass:

```bash
git checkout canary
git pull origin canary
make ci
```

### 2. Update Version Numbers

Update the version constant in the relevant package(s):

- Core: `packages/better_auth/lib/better_auth/version.rb`
- Rails: `packages/better_auth-rails/lib/better_auth/rails/version.rb`
- Sinatra: `packages/better_auth-sinatra/lib/better_auth/sinatra/version.rb`

### 3. Update Changelog

Add a new section to `CHANGELOG.md` in the relevant package(s) with the release date and changes.

### 4. Merge to Main

```bash
git checkout main
git merge canary
git push origin main
```

### 5. Tag the Release

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main --tags
```

### 6. Create/Update Version Branch

```bash
git checkout -b v0.x main    # First time
# or
git checkout v0.x && git merge main  # Subsequent patches
git push origin v0.x
```

### 7. Publish to RubyGems

GitHub Actions handles this automatically when a tag is pushed. The workflow at `.github/workflows/release.yml` builds and publishes the gem(s).

Manual publish (if needed):

```bash
cd packages/better_auth
gem build better_auth.gemspec
gem push better_auth-0.2.0.gem

cd ../better_auth-rails
gem build better_auth-rails.gemspec
gem push better_auth-rails-0.2.0.gem

cd ../better_auth-sinatra
gem build better_auth-sinatra.gemspec
gem push better_auth-sinatra-0.2.0.gem
```

### 8. Post-Release

- Verify the gem is live on [rubygems.org](https://rubygems.org/gems/better_auth)
- Create a GitHub Release from the tag with release notes
- Announce in Discord if significant

## Hotfix Process

For urgent fixes to a released version:

```bash
git checkout v0.x
git checkout -b fix/critical-bug
# ... make fix ...
git commit -m "fix(core): resolve critical auth bypass"
# PR into v0.x, then cherry-pick to canary
```

## Gem Versioning

Each gem has independent versioning:

| Gem | Version File |
|-----|-------------|
| `better_auth` | `packages/better_auth/lib/better_auth/version.rb` |
| `better_auth-rails` | `packages/better_auth-rails/lib/better_auth/rails/version.rb` |
| `better_auth-sinatra` | `packages/better_auth-sinatra/lib/better_auth/sinatra/version.rb` |

The Rails and Sinatra adapters depend on `better_auth ~> 0.1` (pessimistic constraint). Update this when bumping major/minor versions of the core gem.
