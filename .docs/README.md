# Documentation

This directory contains internal documentation for Better Auth Ruby development.

## Structure

### `plans/`
Long-running implementation plans. Plans use checkbox steps so agents can mark progress as phases, upstream parity discoveries, and Ruby-specific adaptations are completed.

### `features/`
Documentation for implemented features and plugins. Feature notes are also where upstream parity decisions and known Ruby/Rails differences are recorded. Each file should explain:
- Link to upstream TypeScript implementation
- How it was adapted to Ruby/Rails
- Key design decisions
- Testing approach
- Usage examples

### `postmortems/`
Documentation for bug fixes and issues. Each file should explain:
- What went wrong
- Root cause analysis
- How it was fixed
- How to prevent it in the future

## Template

See the example files in each directory for the recommended structure.
