# Better Auth Ruby — Integration Examples

This directory contains sample integrations for **Better Auth Ruby** across different application stacks.

Each subfolder is a placeholder for a standalone example project. They do not contain full projects yet; they will be fleshed out as the port progresses.

## Structure

| Folder | Description |
|--------|-------------|
| `vanilla/` | Framework-agnostic (plain Ruby / Rack) integration using the core `better_auth` gem. |
| `rails/` | Integration with **Ruby on Rails** using the `better_auth-rails` adapter. |
| `sinatra/` | Integration with **Sinatra** using the `better_auth-sinatra` adapter. |
| `hanami/` | Integration with **Hanami** using the `better_auth-hanami` adapter. |

## Adding a New Example

1. Create a folder under `examples/<framework>/`.
2. Include a minimal, runnable project that demonstrates authentication setup, session handling, and at least one protected route.
3. Keep dependencies pinned to the local monorepo packages where possible.
