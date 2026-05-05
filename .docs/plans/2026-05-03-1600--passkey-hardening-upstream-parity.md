# Passkey gem hardening & upstream parity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align `better_auth-passkey` with upstream Better Auth passkey behavior where it improves correctness and security, without breaking compatibility or chasing differences Ruby cannot meaningfully mirror.

**Architecture:** Adjust session freshness and error classification on `/passkey/verify-registration`, invalidate stored verification values when verification fails (so challenges are single-use in practice), replace brittle credential introspection with the `webauthn` gem public API, add regression tests for gaps identified versus upstream Vitest and WebAuthn flows.

**Tech Stack:** Ruby 3.x, `better_auth`, `better_auth-passkey`, `webauthn` gem (~3.4), Minitest, StandardRB.

---

## Qué entra y qué no (conclusión explícita)


| Cambio analizado                                                                 | ¿Entra? | Por qué sí / por qué no                                                                                                                                                                                                                                                                                                                                |
| -------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Sesión **fresh** en `verify-registration` cuando hay sesión obligatoria          | **Sí**  | Upstream usa `freshSessionMiddleware` (`upstream/packages/passkey/src/routes.ts` ~516). Ruby ya usa `fresh: true` al resolver usuario en `generate-register-options` (`utils.rb` ~75); cerrar la brecha evita sesiones viejas en verify.                                                                                                               |
| Errores de **WebAuthn en registro**: `BAD_REQUEST` vs `INTERNAL_SERVER_ERROR`    | **Sí**  | **Mejora Ruby, no paridad upstream.** Upstream envuelve TODO el bloque de verify en un `catch` que convierte cualquier error (incluido el `BAD_REQUEST` explícito de `!verified`) a **500** (`routes.ts` ~~663–668). Cambiar a **400** para fallos criptográficos / malformados mejora la semántica HTTP y no rompe el contrato público. Separar errores de verificación (400) de errores inesperados post-verify (500) es hardening. |
| **verify-authentication**: usar **401** en vez de **400** para `WebAuthn::Error` | **No**  | En upstream, `!verified` da **401** (~~787–791), pero el `**catch`** del mismo endpoint devuelve **400** + `AUTHENTICATION_FAILED` (~~847–852). En Ruby `credential.verify` falla con **excepción**, equivalente al camino `catch` → **400**. Cambiar todo a 401 **no** replica upstream y puede romper clientes que esperan 400 en errores de verify. |
| Invalidar challenge al **fallar** verify                                         | **Sí**  | **Mejora Ruby, no paridad upstream.** Upstream solo borra el challenge en éxito (`routes.ts` ~657–659, ~834–836). Invalidar en fallo reduce la ventana de reintentos hasta el TTL; comportamiento más seguro y alineado con “un intento por challenge”. |
| `Credential`: `instance_variable_get(:@response)` → API pública                  | **Sí**  | `WebAuthn::PublicKeyCredential` expone `attr_reader :response` (gem `webauthn`); no hace falta tocar variables internas.                                                                                                                                                                                                                               |
| **deviceType** idéntico a SimpleWebAuthn                                         | **No**  | Depende del modelo de datos del gem Ruby vs `@simplewebauthn/server`; forzar strings TS puede ser incorrecto. Es adaptación aceptable.                                                                                                                                                                                                                 |
| **User handle** (bytes) idéntico al upstream                                     | **No**  | Cambiar el algoritmo invalidaría flujos existentes y no aporta seguridad si sigue siendo aleatorio y RFC-compliant.                                                                                                                                                                                                                                    |
| **Attestation** distinta de `none`                                               | **No**  | Alcance de producto grande (trust anchors, enterprise); no es paridad mínima del plugin “passwordless” típico.                                                                                                                                                                                                                                         |
| Mensaje distinto en **update-passkey** por ownership                             | **No**  | Upstream también usa `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` en update (`routes.ts` ~1028). No hay texto alternativo en upstream que debamos inventar.                                                                                                                                                                                          |
| Paridad de tipos en **afterVerification** con TypeScript                         | **No**  | Los callbacks en Ruby reciben `WebAuthn::Credential` y payloads Ruby; no es posible exportar los mismos tipos TS. La mitigación es **documentación** breve (README del gem), no “simular” structs TS.                                                                                                                                                  |
| Forzar **UV** en `verify` según `authenticator_selection`                        | **No**  | Upstream fija `requireUserVerification: false` en verify (`routes.ts` ~596–597, ~784). Cambiar UV en servidor sin un cambio coordinado en upstream sería una decisión de producto distinta.                                                                                                                                                            |


---

## File map


| File                                                                            | Rol                                                                                               |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb`   | Fresh session en verify; mapa de errores; invalidación de challenge en fallo                      |
| `packages/better_auth-passkey/lib/better_auth/passkey/routes/authentication.rb` | Invalidación de challenge en fallo (antes del `raise`)                                            |
| `packages/better_auth-passkey/lib/better_auth/passkey/credentials.rb`           | `attestation_response` vía `credential.response`                                                  |
| `packages/better_auth-passkey/test/better_auth/passkey/**/*.rb`                 | Tests nuevos o ajustados                                                                          |
| `packages/better_auth-passkey/README.md`                                        | Nota corta sobre forma de los callbacks vs cliente TS (opcional pero recomendado en última tarea) |
| `packages/better_auth-passkey/CHANGELOG.md`                                     | Entrada bajo cabecera Unreleased                                                                  |


---

### Task 1: Sesión fresh en `verify-registration`

**Estado:** completado inline el 2026-05-04. Upstream confirma `freshSessionMiddleware`; Ruby adaptado con `current_session(..., fresh: true)` solo cuando `registration.require_session` es obligatorio.

**Files:**

- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb` (o `test/better_auth/passkey_test.rb` si ahí vive el patrón de sesión)
- [x] **Step 1: Write the failing test**

Añadir un test que: con `registration.require_session` implícito true, simule una sesión **no fresh** (el core expone `ensure_fresh_session!` vía `fresh: true` en `current_session`). El comportamiento esperado tras el fix: `verify-registration` debe responder **403** (`FORBIDDEN` + `SESSION_NOT_FRESH`), igual que `generate-register-options` hoy (`registration_test.rb` ~66–83). Reutiliza el mismo estilo que `packages/better_auth/test/better_auth/routes/session_routes_test.rb` para `fresh: true` si existe patrón exportable; si no, fija `session_max_age` / edad de sesión en el auth de prueba para forzar “stale” según `BetterAuth::Routes.ensure_fresh_session!`.

```ruby
# Ejemplo de intención (ajustar helpers reales del test del paquete):
def test_verify_registration_rejects_stale_session_when_require_session
  # build_auth(session: {fresh_age: 1}), sesión vieja, challenge válido
  # POST verify-registration con cookie de challenge válida
  # assert_raises(BetterAuth::APIError) { ... }
  # assert_equal 403, error.status_code
  # assert_equal BetterAuth::BASE_ERROR_CODES.fetch("SESSION_NOT_FRESH"), error.message
end
```

- [x] **Step 2: Run test — debe fallar**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-passkey
bundle exec ruby -Itest test/better_auth/passkey/routes/registration_test.rb -n /stale/
```

Expected: FAIL (verify acepta sesión stale o el test no compila hasta ajustar helpers).

- [x] **Step 3: Implementación mínima**

En `verify_passkey_registration_endpoint`, donde hoy está:

```ruby
session = require_session ? BetterAuth::Routes.current_session(ctx, sensitive: true) : BetterAuth::Routes.current_session(ctx, allow_nil: true)
```

sustituir por:

```ruby
session = require_session ? BetterAuth::Routes.current_session(ctx, sensitive: true, fresh: true) : BetterAuth::Routes.current_session(ctx, allow_nil: true)
```

- [x] **Step 4: Run test — debe pasar**

```bash
bundle exec ruby -Itest test/better_auth/passkey/routes/registration_test.rb -n /stale/
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb
git commit -m "fix(passkey): require fresh session on verify-registration when session required"
```

---

### Task 2: Errores de verificación de registro → `BAD_REQUEST`; fallos inesperados → `INTERNAL_SERVER_ERROR`

**Estado:** completado inline el 2026-05-04. Diferencia intencional frente a upstream: upstream convierte el bloque completo en 500; Ruby separa errores WebAuthn/ArgumentError como 400 y conserva 500 para fallos inesperados fuera de la verificación criptográfica.

**Files:**

- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb` (o integración en `test/better_auth/passkey_test.rb`)
- [x] **Step 1: Write the failing test**

Test que fuerza un `WebAuthn::Error` en la ruta de verify (p.ej. stub `WebAuthn::Credential.from_create` o `credential.verify` para lanzar `WebAuthn::Error`). Antes del fix el código devuelve **500**; después debe devolver **400** con mensaje `FAILED_TO_VERIFY_REGISTRATION`.

```ruby
def test_verify_registration_maps_webauthn_error_to_bad_request
  WebAuthn::Credential.stub(:from_create, ->(*) { raise WebAuthn::Error, "bad" }) do
    # POST verify-registration con challenge válido en adapter + cookie
    # assert_equal 400, status  # o assert sobre APIError capturado en el harness del paquete
  end
end
```

(Ajustar al harness real: Rack::MockRequest / helper `auth.api` del paquete.)

- [x] **Step 2: Run test — debe fallar**

```bash
bundle exec ruby -Itest test/better_auth/passkey/routes/registration_test.rb -n /maps_webauthn/
```

Expected: FAIL (500 o aserción de código incorrecto).

- [x] **Step 3: Implementación**

Reestructurar el endpoint para que:

1. El bloque de **verificación criptográfica** (`from_create`, `verify`, `after_registration_verification_user_id`) rescate `**WebAuthn::Error`** y `**ArgumentError`** (inputs malformados) y lance:

```ruby
raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
```

2. El `rescue WebAuthn::Error` global que hoy convierte todo en **500** se elimina o se reduce a `**StandardError`** para errores realmente inesperados (p.ej. fallo de `adapter.create` por DB).

> **Importante:** `adapter.create` debe quedar **fuera** del `rescue WebAuthn::Error, ArgumentError` para que un fallo de base de datos no se confunda con un error de verificación. Usar dos niveles de `begin` o un `rescue` específico seguido de `rescue StandardError`.

Ejemplo de forma (adaptar al estilo existente del archivo):

```ruby
Endpoint.new(...) do |ctx|
  # ... setup (origin, verification_token, challenge, session) ...

  credential = nil
  begin
    response = Credentials.webauthn_response(body[:response])
    relying_party = Utils.relying_party(config, ctx, origin: origin)
    credential = WebAuthn::Credential.from_create(response, relying_party: relying_party)
    credential.verify(challenge.fetch("expectedChallenge"), user_verification: false)
    authenticator_data = Credentials.authenticator_data(credential)
    target_user_id = Utils.after_registration_verification_user_id(config, ctx, credential, challenge, response, session)
  rescue WebAuthn::Error, ArgumentError => error
    ctx.context.internal_adapter.delete_verification_by_identifier(verification_token) if verification_token
    ctx.context.logger&.error("Failed to verify registration", error)
    raise APIError.new("BAD_REQUEST", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
  rescue APIError
    ctx.context.internal_adapter.delete_verification_by_identifier(verification_token) if verification_token
    raise
  end

  data = ctx.context.adapter.create(
    model: "passkey",
    data: {
      # ...
    }
  )
  ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
  ctx.json(Credentials.wire(data))
rescue StandardError => error
  ctx.context.logger&.error("Failed to verify registration", error)
  raise APIError.new("INTERNAL_SERVER_ERROR", message: ErrorCodes::PASSKEY_ERROR_CODES.fetch("FAILED_TO_VERIFY_REGISTRATION"))
end
```

(Adaptar exactamente al estilo `Endpoint` del archivo; el punto clave es no capturar `adapter.create` con `WebAuthn::Error`.)

- [x] **Step 4: Run tests del paquete passkey**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-passkey
bundle exec rake test
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb
git commit -m "fix(passkey): return 400 for registration verify crypto failures"
```

---

### Task 3: Borrar verificación al fallar `verify-registration` y `verify-authentication`

**Estado:** completado inline el 2026-05-04 para fallos posteriores a obtener un challenge. Esto es hardening Ruby; upstream v1.6.9 borra el challenge en éxito pero no en todos los fallos.

**Files:**

- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/registration.rb`
- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/routes/authentication.rb`
- Test: `test/better_auth/passkey_test.rb` o `test/better_auth/passkey/challenges_test.rb` + flujo HTTP
- [x] **Step 1: Write the failing test**

1. Almacenar challenge válido, llamar verify con respuesta inválida (o stub que lance), asertar que `internal_adapter.find_verification_value(token)` es **nil** tras la respuesta (o que no existe fila para ese identifier).
2. Repetir patrón para authentication verify.

- [x] **Step 2: Run test — debe fallar**

Expected: verificación aún presente hasta TTL.

- [x] **Step 3: Implementación**

En cada endpoint, cuando ya se tuvo `verification_token` y el fallo ocurre **después** de obtener el challenge (verify crypto, `afterVerification`, mismatch de sesión, etc.), llamar:

```ruby
ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
```

en los bloques `rescue` relevantes **antes** de re-lanzar `APIError`. No borrar si el fallo fue "sin cookie" (token nil).

Para **registration**, cubrir al menos:
- `WebAuthn::Error`, `ArgumentError` (verificación criptográfica) → 400
- `APIError` lanzado por `after_registration_verification_user_id` (`RESOLVED_USER_INVALID`, `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`) → preservar código original, pero borrar challenge
- `StandardError` inesperado (p.ej. DB) → 500

Para **authentication** (`authentication.rb` ~86–88), dentro del `rescue WebAuthn::Error, ArgumentError`:

```ruby
ctx.context.internal_adapter.delete_verification_by_identifier(verification_token)
```

(verificar que `verification_token` está en alcance; ya lo es desde línea ~48.)

- [x] **Step 4: Run `bundle exec rake test` en passkey**
- [ ] **Step 5: Commit**

```bash
git commit -m "fix(passkey): invalidate WebAuthn challenge after failed verify"
```

---

### Task 4: `Credentials.attestation_response` sin `instance_variable_get`

**Estado:** completado inline el 2026-05-04 usando el reader público `credential.response` del gem `webauthn`.

**Files:**

- Modify: `packages/better_auth-passkey/lib/better_auth/passkey/credentials.rb`
- Test: `packages/better_auth-passkey/test/better_auth/passkey/credentials_test.rb`
- [x] **Step 1: Write test** que espía que no se llama `instance_variable_get` (opcional) o simplemente que `attestation_response` devuelve el mismo objeto que `credential.response` para un double con `response`.
- [x] **Step 2: Implementación**

```ruby
def attestation_response(credential)
  credential.respond_to?(:response) ? credential.response : nil
end
```

- [x] **Step 3: Run `bundle exec ruby -Itest test/better_auth/passkey/credentials_test.rb`**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(passkey): read attestation via public credential.response"
```

---

### Task 5: Tests de regresión adicionales (paridad upstream / huecos WebAuthn)

**Estado:** parcialmente completado/descartado el 2026-05-04. Los escenarios de `afterVerification` inválido y mismatch de usuario ya existían en `packages/better_auth-passkey/test/better_auth/passkey_test.rb`; no se duplicaron. Se agregó cobertura de challenge expirado en `verify-authentication`. Suite del paquete y StandardRB pasan.

**Files:**

- Modify: `packages/better_auth-passkey/test/better_auth/passkey/routes/registration_test.rb`
- Modify: `packages/better_auth-passkey/test/better_auth/passkey/routes/authentication_test.rb`
- Opcional: `test/better_auth/passkey_test.rb`
- [x] **Step 1: Portar escenarios de `upstream/packages/passkey/src/passkey.test.ts`** que aún falten en Ruby:
  - `afterVerification` devuelve `userId` que **no es String** → **400** + `RESOLVED_USER_INVALID` (ver `utils.rb` / flujo actual).
  - Sesión presente y `afterVerification` intenta **userId** distinto al usuario de sesión → **401** + `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY`.
- [x] **Step 2: Authentication — challenge expirado**

Forzar `expiresAt` en el registro de verification del `internal_adapter` al pasado (como ya hacéis en registro) y asertar **400** + `CHALLENGE_NOT_FOUND` en verify-authentication.

- [x] **Step 3: Run suite**

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-passkey
bundle exec rake test
```

- [ ] **Step 4: Commit**

```bash
git commit -m "test(passkey): cover afterVerification edge cases and expired auth challenge"
```

---

### Task 6: Documentación y changelog

**Estado:** completado inline el 2026-05-04. Suite del paquete y StandardRB pasan.

**Files:**

- Modify: `packages/better_auth-passkey/README.md` (sección “Callbacks” o “Differences from TypeScript”)
- Modify: `packages/better_auth-passkey/CHANGELOG.md`
- [x] **Step 1:** En README, 4–6 líneas: los callbacks `registration.after_verification` / `authentication.after_verification` reciben objetos del gem `**webauthn`**, no los tipos `VerifiedRegistrationResponse` / `VerifiedAuthenticationResponse` de Node.
- [x] **Step 2:** CHANGELOG bajo `## [Unreleased]` con viñetas: fresh session en verify-registration; 400 en fallos de verify de registro; invalidación de challenge en fallo; uso de `credential.response`.
- [ ] **Step 3: Commit**

```bash
git commit -m "docs(passkey): note callback shapes and changelog for hardening"
```

---

## Self-review (skill checklist)

1. **Spec coverage:** Cada hallazgo “entra” en la tabla tiene al menos una tarea (fresh session, errores 400, invalidación challenge, `response` público, tests, docs).
2. **Placeholder scan:** Sin TBD; comandos y rutas concretas.
3. **Consistencia:** `verification_token` y `ErrorCodes::PASSKEY_ERROR_CODES` usados igual que en el código actual.

---

## Execution handoff

Plan guardado en `.docs/plans/2026-05-03-1600--passkey-hardening-upstream-parity.md`.

**Opciones de ejecución:**

1. **Subagent-Driven (recomendado)** — subagente por tarea con revisión entre tareas; skill `superpowers:subagent-driven-development`.
2. **Inline** — ejecutar tareas en esta sesión con checkpoints; skill `superpowers:executing-plans`.

¿Cuál prefieres?
