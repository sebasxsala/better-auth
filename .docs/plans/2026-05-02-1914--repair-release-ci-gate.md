# Repair release CI gate

## Context

The `v0.6.1` release tags were pushed to commit `36db41f1a33a5493dd7e16264fa2acd9b14cc5d9` after CI had passed on `main`.

The release workflow's `Verify CI passed` job queried:

```bash
/repos/${REPO}/commits/${COMMIT_SHA}/check-runs?per_page=100
```

Because twelve package tags were pushed to the same commit, the release workflows created enough check runs that the first page no longer included the `CI / ci` aggregator. The unfiltered query returned 100 check runs and no `ci` check, while the same commit queried with `check_name=ci` returned two successful checks from `main` and `canary`.

## Plan

- [x] Confirm root cause from GitHub Actions check-run data.
- [x] Update `.github/workflows/release.yml` so the CI gate queries the `ci` check by name.
- [x] Choose the recovery version strategy after checking which `0.6.1` gems were already published.
- [x] Apply the release version changes from `main`, not `canary`.
- [x] Update release docs so all package tags are listed.
- [x] Verify the workflow and version metadata locally.
- [x] Commit the fix and version changes.
- [x] Push `main`, wait for CI, then create package tags from `main`.

## Release decision notes

- Reusing `0.6.1` is only viable for gems that did not publish and would require deleting/recreating existing remote tags for those packages so the fixed workflow file is used.
- RubyGems versions are immutable, so gems that already published `0.6.1` cannot publish `0.6.1` again.
- If any package already has `0.6.1`, the safest consistent recovery is to publish `0.6.2` for all release packages from `main`.
- RubyGems already has `0.6.1` for `better_auth`, `better_auth-rails`, `better_auth-passkey`, and `better_auth-sinatra`.
- Recovery version selected: `0.6.2` for all twelve packages from `main`.
- Commit `c8fe191961861fe7e1aabbecd1ed4abf89a11bc8` was pushed to `main` and passed CI.
- Tags `better_auth*-v0.6.2` were created at `c8fe191961861fe7e1aabbecd1ed4abf89a11bc8`.
- Pushing twelve tags together did not create tag push workflow runs. GitHub does not reliably emit push events for bulk tag pushes over its tag creation limit, so the existing `Release` workflow was dispatched manually for each tag with `dry_run=false`.
- All twelve `Release` workflow runs completed successfully, and RubyGems shows `0.6.2` for every package.
