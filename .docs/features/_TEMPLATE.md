# Feature: [Feature Name]

## Parity Status Rule

Use `Complete` only when every server-relevant upstream runtime behavior has a Ruby test and documented Ruby adaptations are intentional. Keep the feature `Partial` when upstream has unported edge cases, missing route matrices, missing adapter coverage, or unresolved client/server scope decisions.

**Upstream Reference:** `upstream/packages/better-auth/src/path/to/feature.ts`

## Summary

Brief description of what this feature does.

## Upstream Implementation

Explain how the feature works in the TypeScript version:
- Key TypeScript concepts used
- Important files/classes
- Overall architecture

## Ruby/Rails Adaptation

Explain how you translated it to Ruby/Rails:

### Key Differences
- TypeScript Promise → Ruby fiber/thread (if applicable)
- TypeScript decorators → Ruby modules/concerns
- etc.

### Design Decisions
Why you made certain choices when adapting to Ruby:
- Used X pattern instead of Y because...
- Leveraged Rails feature Z...

## Implementation

Link to key files:
- `packages/better_auth/lib/better_auth/feature.rb:123`
- `packages/better_auth-rails/lib/better_auth/rails/feature_helper.rb:45`

## Testing

How to test this feature:
```bash
bundle exec rake test
```

Key test files:
- `packages/better_auth/test/feature_test.rb`

## Usage Example

```ruby
# Example code showing how to use the feature
BetterAuth.configure do |config|
  config.feature.enabled = true
end
```

## Notes

Any additional context, gotchas, or future improvements.
