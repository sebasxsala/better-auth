# Release Process

This Ruby port follows upstream's tag-driven release shape: merging code does not publish packages. A release happens when a version commit is already on the right branch and a `v*` tag is pushed.

## Branches

- `canary` is the integration branch. Merge completed feature branches here first.
- `main` is the stable release branch.
- Maintenance branches use `vX.Y.x`, for example `v0.1.x`, when an older line needs fixes after `main` has moved on.

Do not create separate folders for supported Rails lines. Keep compatibility in gem constraints and CI coverage. If a future release line needs to keep Rails 6 support while `main` moves to newer Rails-only behavior, branch from the last compatible commit into a maintenance branch and tag releases from that branch.

## Stable Release

1. Merge the desired `canary` changes into `main`.
2. Bump the relevant gem version file or files:
   - `packages/better_auth/lib/better_auth/version.rb`
   - `packages/better_auth-rails/lib/better_auth/rails/version.rb`
3. Let CI pass on `main`.
4. Push a tag matching the version, for example:

   ```bash
   git tag v0.1.2
   git push origin v0.1.2
   ```

The release workflow publishes any gem whose version equals the tag version. If both gems have `0.1.2`, both publish. If only `better_auth-rails` has `0.1.2`, only the Rails gem and its `better_auth_rails` compatibility alias publish.

Stable tags must be contained in `main` or a `vX.Y.x` maintenance branch. The workflow rejects stable tags from `canary`.

## Prerelease

Use RubyGems-compatible prerelease versions in the gem version files, for example:

```ruby
VERSION = "0.2.0.beta.1"
```

Then push the matching tag:

```bash
git tag v0.2.0.beta.1
git push origin v0.2.0.beta.1
```

Prerelease tags may be created from `canary`, `main`, or a maintenance branch.

## Maintenance Release

For an older supported line:

```bash
git switch -c v0.1.x v0.1.3
# cherry-pick or commit the fix
# bump to 0.1.4
git tag v0.1.4
git push origin v0.1.x v0.1.4
```

RubyGems versioning separates the release lines. Users who need that line pin the gem with normal version constraints, for example `~> 0.1.0`.

## Dry Run

Use the manual `Release` workflow with `dry_run: true` to build and validate the gems without publishing. Publishing only happens from pushed `v*` tags.
