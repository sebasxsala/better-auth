# Redis Storage Upstream Test Parity Plan

## Summary
Guardar el plan en `.docs/plans/2026-04-29-redis-storage-upstream-test-parity.md` y traducir primero los tests faltantes de upstream a Minitest antes de tocar implementación.

Upstream relevante:
- `upstream/packages/redis-storage/src/redis-storage.ts`: no tiene tests unitarios propios.
- `upstream/e2e/smoke/test/redis.spec.ts`: 4 smoke tests aplicables a servidor.

Estado Ruby:
- `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`: 21 tests pasan.
- `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb`: 3 tests pasan contra Redis real con permisos de red.
- No hay tests browser/client que aplicar para este paquete.

## Tests Faltantes A Traducir
Agregar/ajustar en `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb`:

- [x] `test_real_redis_stores_session_data_after_email_signup`
  - Traduce upstream `"should store session data in Redis after email signup"`.
  - Usar `database: :memory`, `email_and_password: {enabled: true}`, Redis real y prefijo único.
  - Assert exacto: `storage.listKeys.length == 2`, una key `active-sessions-*`, una session key, payload JSON con `user.id`, `session.id`, y token igual al signup.

- [x] `test_real_redis_stores_session_id_when_store_session_in_database_is_true`
  - Traduce upstream `"should have session id in Redis when storeSessionInDatabase is true"`.
  - Usar `session: {store_session_in_database: true}`.
  - Assert exacto igual al upstream: 2 keys en Redis y payload con `user.id`, `session.id`, `session.token`.

- [x] `test_real_redis_stores_stateless_google_oauth_session`
  - Traduce upstream `"should store session data in Redis with stateless mode and Google OAuth"`.
  - Usar `database: nil`, `session: {cookie_cache: {enabled: true, max_age: 7.days, strategy: "jwe", refresh_cache: true}}`, `account: {store_state_strategy: "cookie", store_account_cookie: true}`.
  - Usar `BetterAuth::SocialProviders.google(...)` con `get_user_info` o stub de token exchange para evitar red externa.
  - Flujo: `sign_in_social`, extraer `state`, llamar `callback_oauth`, assert `302` hacia `/callback`.
  - Assert Redis: exactamente 2 keys, payload de sesión con `user.id`, `session.id`, `user.email == "google-user@example.com"`.

- [x] `test_real_redis_google_oauth_uses_custom_authorization_endpoint`
  - Traduce upstream `"should use custom authorization endpoint for Google OAuth provider"`.
  - Usar `database: nil`, Redis real y `BetterAuth::SocialProviders.google(..., authorization_endpoint: custom_endpoint)`.
  - Assert: respuesta 200, URL incluye `http://localhost:8080/custom-oauth/authorize`, no incluye `accounts.google.com`, incluye `localhost:8080`.
  - Nota: upstream lo agrupa en Redis smoke aunque no valida escritura Redis; mantenerlo por paridad.

## Implementation Order
- [x] Crear el archivo de plan con este contenido en `.docs/plans/2026-04-29-redis-storage-upstream-test-parity.md`.
- [x] Separar o reforzar el test integrado actual que combina `store_session_in_database: false/true`, para que existan los dos nombres traducidos y asserts exactos upstream.
- [x] Agregar helpers privados reutilizables:
  - `build_auth(storage, store_session_in_database:)`
  - `build_stateless_google_auth(storage, authorization_endpoint: nil)`
  - `extract_state(url)`
  - `session_payload_from_storage(storage)`
  - `fake_jwt(payload)` si se decide simular `id_token`.
- [x] Ejecutar sólo los tests nuevos y confirmar si fallan o pasan antes de tocar implementación.
- [x] Si fallan por comportamiento real, aplicar implementación mínima después de tener el fallo rojo confirmado. No aplicó: los tests nuevos pasaron con la implementación actual.
- [x] Ejecutar suite del paquete completa.

## Test Commands
- Unit baseline:
  `rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_test.rb`

- Integration baseline:
  `env REDIS_INTEGRATION=1 REDIS_URL=redis://127.0.0.1:6379/15 rbenv exec bundle exec ruby -Itest test/better_auth/redis_storage_integration_test.rb --verbose`

## Assumptions
- Incluir todos los smoke tests upstream de Redis que son server-side; excluir sólo browser/client, que no existen para este paquete.
- Usar Redis real para los tests traducidos, porque upstream también valida integración real.
- No cambiar versiones de gemas ni release metadata.
