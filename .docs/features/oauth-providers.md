# OAuth Providers

**Upstream Reference:** `upstream/packages/better-auth/src/plugins/oauth/`

## Summary

OAuth providers allow users to authenticate using third-party services like GitHub, Google, Twitter, etc.

## Upstream Implementation

The TypeScript version uses:
- Fetch API for HTTP requests
- Zod for schema validation
- Arctic library for OAuth flows
- Plugin system for extensibility

## Ruby/Rails Adaptation

### Key Differences
- **HTTP Client:** Using Faraday instead of Fetch API
- **Validation:** Using dry-validation instead of Zod
- **OAuth Library:** Considering omniauth integration vs custom implementation

### Design Decisions
- Chose to build on top of omniauth for Rails compatibility
- Core gem provides abstract OAuth client
- Rails adapter integrates with omniauth strategies

## Implementation

- `packages/better_auth/lib/better_auth/oauth/client.rb` - Core OAuth client
- `packages/better_auth-rails/lib/better_auth/rails/oauth_helper.rb` - Rails integration

## Testing

```bash
cd packages/better_auth
bundle exec rake test TEST=test/oauth_test.rb
```

## Usage Example

```ruby
# config/initializers/better_auth.rb
BetterAuth.configure do |config|
  config.oauth.providers = [
    {
      id: "github",
      client_id: ENV["GITHUB_CLIENT_ID"],
      client_secret: ENV["GITHUB_CLIENT_SECRET"]
    }
  ]
end
```

## Notes

- Each provider needs specific scopes and callback handling
- Token refresh logic varies by provider
- See upstream for latest provider additions
