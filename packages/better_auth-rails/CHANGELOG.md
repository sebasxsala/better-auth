# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2026-03-22

### Fixed

- Fixed gemspec files list to use `Dir.glob` instead of `git ls-files` for better CI compatibility
- Fixed dependency constraints for railties and activesupport (now `>= 6.0, < 9`)
- Removed better_auth_rails compatibility gem (RubyGems doesn't allow similar names)

### Added

- Initial Rails adapter setup
- Basic gem structure

## [0.1.0] - 2026-03-17

### Added

- Initial project setup
