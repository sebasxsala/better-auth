# Changelog

## Unreleased

- Apply `advanced[:database][:default_find_many_limit]` to uncapped `find_many` calls and one-to-many Mongo `$lookup` joins, defaulting to 100 when omitted.
- Match upstream Mongo where-clause semantics for mixed connectors by bucketing multi-clause filters into `$and` and `$or` arrays instead of left-fold nesting.
- Allow scalar values for `in` and `not_in` filters, matching upstream's single-value array coercion.

## 0.1.1 - 2026-04-30

- Fixed inferred limited joins so explicit relation and limit configuration is preserved.
- Added MongoDB upstream parity coverage using a fake Mongo adapter harness.

## 0.1.0

- Extract MongoDB adapter support into the `better_auth-mongo-adapter` package.
- Align MongoDB adapter behavior with upstream Better Auth v1.6.9, including where-clause key variants, falsey value handling, ID normalization, and external adapter compatibility coverage.
