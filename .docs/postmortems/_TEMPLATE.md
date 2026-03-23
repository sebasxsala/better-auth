# Postmortem: [Issue Title]

**Issue:** #123 (link to GitHub issue if applicable)

**Date:** 2026-03-22

## Summary

One-paragraph summary of what went wrong.

## Timeline

- **YYYY-MM-DD HH:MM** - Issue first reported
- **YYYY-MM-DD HH:MM** - Investigation started
- **YYYY-MM-DD HH:MM** - Root cause identified
- **YYYY-MM-DD HH:MM** - Fix deployed

## Impact

What broke and who was affected:
- Users couldn't authenticate
- Sessions were being lost
- etc.

## Root Cause

Detailed explanation of what caused the issue:
- Code snippet showing the bug
- Why it happened (logic error, race condition, etc.)

## Resolution

How it was fixed:
- Code changes made
- Files modified: `path/to/file.rb:123`
- Why this approach was chosen

## Lessons Learned

- What we learned from this issue
- How to prevent similar issues in the future
- Any follow-up work needed

## Upstream Comparison

If this bug didn't exist in upstream TypeScript version:
- Why it occurred in the Ruby port
- What was different about our implementation

If it did exist in upstream:
- Link to their fix
- How we adapted their solution
