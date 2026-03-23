# AGENTS.md - Better Auth Ruby Workspace

## What is Better Auth Ruby?

Better Auth Ruby is a **Ruby/Rails port** of [better-auth](https://github.com/better-auth/better-auth), the popular TypeScript authentication library. The goal is to bring the same developer experience, features, and plugin ecosystem to the Ruby world.

**The upstream TypeScript implementation lives in `upstream/` as a git submodule.** This is the source of truth for how features should work. When implementing or modifying features, always reference `upstream/` to understand the original implementation and adapt it idiomatically to Ruby/Rails.

## Monorepo Structure

- **`better_auth`** - Core authentication library (framework-agnostic, Rack-based)
- **`better_auth-rails`** - Rails adapter with middleware, helpers, and generators

## Monorepo Structure

```
better-auth/                    # Workspace root (this file)
├── upstream/                   # Submodule: better-auth TypeScript original
├── packages/
│   ├── better_auth/            # Core gem (see packages/better_auth/AGENTS.md)
│   └── better_auth-rails/      # Rails adapter (see packages/better_auth-rails/AGENTS.md)
├── AGENTS.md                   # This file (workspace-level)
├── CLAUDE.md                   # Symlink to AGENTS.md
├── Gemfile                     # Workspace Gemfile
└── Makefile                    # Workspace commands
```

## ⚠️ IMPORTANT - Package-Specific Guidance

**When working on a specific package, you MUST read and follow the AGENTS.md in that package's directory:**

- Working on `packages/better_auth/` → Read `packages/better_auth/AGENTS.md`
- Working on `packages/better_auth-rails/` → Read `packages/better_auth-rails/AGENTS.md`

Each package has its own specific rules, testing setup, and conventions.

## Development Commands (Workspace Level)

```bash
# Install all dependencies
make install

# Run all tests across all packages
make test

# Run linter on all packages
make lint

# Run full CI (lint + test)
make ci

# Console with all packages loaded
make console
```

For package-specific commands, see the Makefile in each package directory.

## Git Workflow

- **`main`** - Production-ready code, releases are tagged from here
- **`canary`** - Development/integration branch (PRs target this)
- **`upstream`** - Reference to original TypeScript repo (submodule)

### Branch Strategy

1. **Feature Development:**
   - Create branch from `canary`: `git checkout -b feat/feature-name`
   - Make changes
   - PR targets `canary`

2. **Release Process:**
   - When `canary` is stable, merge to `main`
   - Create version bump commit
   - Create git tag: `git tag -a v0.1.0 -m "Release v0.1.0"`
   - Push tags: `git push origin main --tags`
   - GitHub Actions publishes to RubyGems automatically

### Commit Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(scope): description` - New features
- `fix(scope): description` - Bug fixes
- `docs(scope): description` - Documentation
- `chore(scope): description` - Maintenance
- `test(scope): description` - Tests

Examples:
- `feat(core): add JWT token validation`
- `fix(rails): resolve session middleware issue`
- `docs: update API reference`

## Code Style (General)

- StandardRB for Ruby linting
- 2 spaces indentation
- snake_case for files/methods/variables
- CamelCase for classes/modules
- SCREAMING_SNAKE_CASE for constants
- `frozen_string_literal: true` pragma in all Ruby files

## After Everything is Done

**Unless the user asked for it or you are working on CI, DO NOT COMMIT**

- Make sure `make lint` passes
- Make sure `make test` passes
- Follow package-specific AGENTS.md guidance
