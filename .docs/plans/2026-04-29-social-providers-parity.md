# Social Providers Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Alcanzar paridad funcional alta (objetivo 100% cuando aplique) entre Ruby y upstream para social providers, cerrando gaps de lógica y cobertura de pruebas.

**Estado 2026-04-29:** Implementado en `packages/better_auth`. Los gaps descritos se confirmaron contra `upstream/packages/core/src/social-providers`:

- WeChat Ruby solo customizaba authorization URL; upstream también requiere token exchange por GET con `appid`/`secret`, refresh por GET con `appid`, userinfo por GET con `openid`, propagación de `openid`/`unionid`, y `lang=cn` por defecto en autorización.
- Railway Ruby usaba OAuth genérico; upstream usa HTTP Basic en token exchange y refresh, sin mandar `client_id`/`client_secret` en el body.
- Google y Vercel Ruby no rechazaban authorization URL sin `code_verifier`; upstream lo exige explícitamente.
- La cobertura Ruby no tenía asserts para esos comportamientos finos. Se agregaron tests focalizados y pasaron.

**Verificación ejecutada:**

- `rbenv exec bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n '/wechat_|railway_.*basic|google_and_vercel_require_code_verifier/'` -> PASS, 8 runs / 36 assertions
- `rbenv exec bundle exec ruby -Itest test/better_auth/social_providers_test.rb` -> PASS, 31 runs / 267 assertions
- `rbenv exec bundle exec ruby -Itest test/better_auth/routes/social_test.rb` -> PASS, 22 runs / 89 assertions
- `env RUBOCOP_CACHE_ROOT=/private/tmp/rubocop_cache rbenv exec bundle exec standardrb` -> PASS
- `rbenv exec bundle exec rake test` -> no concluyente en sandbox: falló por conexiones locales bloqueadas a Postgres/MySQL/MSSQL y por tests que levantan `TCPServer` en `127.0.0.1`; la falla aislada de magic link se verificó con test focalizado y pasó.

**Paridad resultante para los gaps auditados:** cerrada para WeChat, Railway, Google PKCE y Vercel PKCE. El cálculo del plan queda en 100% para los ejes definidos, con la precisión de que este porcentaje se limita a la matriz del plan, no a una prueba formal exhaustiva de cada proveedor posible.

**Architecture:** La estrategia usa TDD en capas: primero auditoría de paridad con matriz explícita por proveedor/caso, luego pruebas faltantes que fallen, después implementación mínima y finalmente regresión y reporte de porcentaje antes/después. Se priorizan diferencias con impacto real de autenticación OAuth (token exchange, verificación de ID token, mapping de perfil, flujos callback). Las diferencias no trasladables por diseño Ruby se documentan explícitamente como exclusiones.

**Tech Stack:** Ruby (Minitest, Rack, Net::HTTP), BetterAuth core gem, upstream Better Auth TypeScript (`packages/better-auth`, `packages/core`)

---

### Task 1: Auditoría de paridad baseline

**Files:**

- Modify: `docs/superpowers/plans/2026-04-29-social-providers-parity.md`
- Test reference: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Upstream reference: `upstream/packages/better-auth/src/social.test.ts`
- Upstream reference: `upstream/packages/core/src/social-providers/*.ts`
- **Step 1: Crear matriz de paridad en el plan (providers + casos críticos)**

```markdown
## Matriz de paridad inicial (baseline)

### Eje A: Providers disponibles
- Upstream core providers: 36
- Ruby providers: 36
- Cobertura A = 36/36 = 100%

### Eje B: Casos críticos upstream (24 casos relevantes)
- URL auth + scopes/default scopes
- PKCE/code_verifier
- validateAuthorizationCode por proveedor
- refreshAccessToken por proveedor
- verifyIdToken (Google/Apple/Microsoft)
- getUserInfo mapping
- callback/new user/existing user
- callback URL hardening y state hardening
- account linking social

Cobertura B inicial = 17/24 = 70.8%

### Eje C: Compatibilidad de lógica específica por proveedor (12 checks)
- google codeVerifier requerido
- google audience múltiple
- apple nombre desde token.user
- microsoft tenant issuer
- microsoft profile photo
- microsoft public client sin client secret
- github user+emails merge
- discord avatar fallback
- vercel codeVerifier requerido
- vercel preferred_username fallback
- railway token auth basic
- wechat token/userinfo flujo no estándar

Cobertura C inicial = 8/12 = 66.7%
```

- **Step 2: Ejecutar verificación rápida de baseline local**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb`
Expected: PASS parcial/total del archivo actual sin nuevos asserts de paridad.

- **Step 3: Registrar porcentaje inicial total con fórmula explícita**

```markdown
## Cálculo de % inicial
Paridad% = (A + B + C) / 3
Paridad inicial = (100 + 70.8 + 66.7) / 3 = 79.2%
```

- **Step 4: Commit de snapshot de auditoría**

```bash
git add docs/superpowers/plans/2026-04-29-social-providers-parity.md
git commit -m "docs(plan): define social providers parity baseline and methodology"
```

### Task 2: Agregar tests faltantes para `wechat` (flujo no estándar)

**Files:**

- Modify: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/wechat.rb`
- **Step 1: Escribir test que falle para intercambio de token WeChat con parámetros no estándar**

```ruby
def test_wechat_validate_authorization_code_uses_appid_secret_and_get_endpoint
  captured_url = nil
  get_json = lambda do |url, _headers = {}|
    captured_url = url
    {"access_token" => "wechat-access", "refresh_token" => "wechat-refresh", "expires_in" => 7200, "openid" => "openid-1", "scope" => "snsapi_login"}
  end

  provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")
  tokens = nil
  BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
    tokens = provider.fetch(:validate_authorization_code).call(code: "code-1")
  end

  assert_includes captured_url, "appid=wx-app"
  assert_includes captured_url, "secret=wx-secret"
  assert_includes captured_url, "grant_type=authorization_code"
  assert_equal "wechat-access", tokens.fetch("accessToken")
end
```

- **Step 2: Ejecutar test para confirmar fallo**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n /wechat_validate_authorization_code_uses_appid_secret_and_get_endpoint/`
Expected: FAIL porque `wechat.rb` usa `oauth_provider` genérico y no usa `appid/secret` en GET.

- **Step 3: Escribir test que falle para `get_user_info` usando `openid` devuelto en token**

```ruby
def test_wechat_get_user_info_uses_openid_and_maps_unionid_fallback
  captured_url = nil
  get_json = lambda do |url, _headers = {}|
    captured_url = url
    {"openid" => "openid-1", "unionid" => "union-1", "nickname" => "wechat-user", "headimgurl" => "https://wechat/avatar.png"}
  end

  provider = BetterAuth::SocialProviders.wechat(client_id: "wx-app", client_secret: "wx-secret")
  info = nil
  BetterAuth::SocialProviders::Base.stub(:get_json, get_json) do
    info = provider.fetch(:get_user_info).call("accessToken" => "wechat-access", "openid" => "openid-1")
  end

  assert_includes captured_url, "openid=openid-1"
  assert_equal "union-1", info.fetch(:user).fetch(:id)
  assert_equal false, info.fetch(:user).fetch(:emailVerified)
end
```

- **Step 4: Ejecutar test para confirmar fallo**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n /wechat_get_user_info_uses_openid_and_maps_unionid_fallback/`
Expected: FAIL por ausencia de lógica custom en `wechat.rb`.

- **Step 5: Commit de pruebas en rojo**

```bash
git add packages/better_auth/test/better_auth/social_providers_test.rb
git commit -m "test(social): add failing wechat parity coverage"
```

### Task 3: Implementación mínima `wechat` para pasar pruebas

**Files:**

- Modify: `packages/better_auth/lib/better_auth/social_providers/wechat.rb`
- Test: `packages/better_auth/test/better_auth/social_providers_test.rb`
- **Step 1: Implementar validateAuthorizationCode no estándar (GET + appid/secret)**

```ruby
provider[:validate_authorization_code] = lambda do |data|
  url = Base.authorization_url("https://api.weixin.qq.com/sns/oauth2/access_token", {
    appid: client_id,
    secret: client_secret,
    code: data[:code],
    grant_type: "authorization_code"
  })
  payload = Base.get_json(url)
  Base.normalize_tokens(payload).merge("openid" => payload["openid"], "unionid" => payload["unionid"])
end
```

- **Step 2: Implementar getUserInfo no estándar (GET con openid en query)**

```ruby
provider[:get_user_info] = lambda do |tokens|
  openid = tokens["openid"] || tokens[:openid]
  next nil if openid.to_s.empty?

  url = Base.authorization_url("https://api.weixin.qq.com/sns/userinfo", {
    access_token: Base.access_token(tokens),
    openid: openid,
    lang: "zh_CN"
  })
  profile = Base.get_json(url)
  next nil unless profile

  user = {
    id: profile["unionid"] || profile["openid"] || openid,
    name: profile["nickname"],
    email: profile["email"],
    image: profile["headimgurl"],
    emailVerified: false
  }
  {user: Base.apply_profile_mapping(user, profile, Base.normalize_options(options)), data: profile}
end
```

- **Step 3: Ejecutar tests de `wechat`**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n /wechat_/`
Expected: PASS en los nuevos casos.

- **Step 4: Commit de implementación mínima**

```bash
git add packages/better_auth/lib/better_auth/social_providers/wechat.rb packages/better_auth/test/better_auth/social_providers_test.rb
git commit -m "fix(social): implement wechat non-standard oauth flow parity"
```

### Task 4: Agregar tests faltantes para `railway` y requisitos de PKCE

**Files:**

- Modify: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/railway.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/vercel.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/google.rb`
- **Step 1: Escribir test en rojo para `railway` token exchange con Basic auth**

```ruby
def test_railway_validate_authorization_code_uses_basic_auth_header
  captured_headers = nil
  post_form = lambda do |_url, _form, headers = {}|
    captured_headers = headers
    {"access_token" => "railway-access"}
  end

  provider = BetterAuth::SocialProviders.railway(client_id: "railway-id", client_secret: "railway-secret")
  BetterAuth::SocialProviders::Base.stub(:post_form_json, post_form) do
    provider.fetch(:validate_authorization_code).call(code: "code", code_verifier: "verifier", redirect_uri: "http://localhost/callback")
  end

  assert_match(/\ABasic /, captured_headers.fetch("Authorization"))
end
```

- **Step 2: Escribir test en rojo para exigir `code_verifier` en Google/Vercel**

```ruby
def test_google_and_vercel_require_code_verifier_for_authorization_url
  google = BetterAuth::SocialProviders.google(client_id: "google-id", client_secret: "google-secret")
  vercel = BetterAuth::SocialProviders.vercel(client_id: "vercel-id", client_secret: "vercel-secret")

  assert_raises(BetterAuth::Error) { google.fetch(:create_authorization_url).call(state: "state", redirect_uri: "http://localhost/google") }
  assert_raises(BetterAuth::Error) { vercel.fetch(:create_authorization_url).call(state: "state", redirect_uri: "http://localhost/vercel") }
end
```

- **Step 3: Ejecutar tests para confirmar fallos**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n /(railway_validate_authorization_code_uses_basic_auth_header|google_and_vercel_require_code_verifier_for_authorization_url)/`
Expected: FAIL.

- **Step 4: Commit de pruebas en rojo**

```bash
git add packages/better_auth/test/better_auth/social_providers_test.rb
git commit -m "test(social): add failing railway and pkce parity tests"
```

### Task 5: Implementación mínima `railway` + reglas PKCE

**Files:**

- Modify: `packages/better_auth/lib/better_auth/social_providers/railway.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/google.rb`
- Modify: `packages/better_auth/lib/better_auth/social_providers/vercel.rb`
- Test: `packages/better_auth/test/better_auth/social_providers_test.rb`
- **Step 1: Implementar Basic auth para token/refresh en `railway.rb`**

```ruby
credentials = Base64.strict_encode64("#{client_id}:#{client_secret}")
provider[:validate_authorization_code] = lambda do |data|
  Base.post_form_json("https://backboard.railway.com/oauth/token", {
    grant_type: "authorization_code",
    code: data[:code],
    code_verifier: data[:code_verifier] || data[:codeVerifier],
    redirect_uri: data[:redirect_uri] || data[:redirectURI]
  }, {"Authorization" => "Basic #{credentials}"})
end
```

- **Step 2: Enforzar `code_verifier` requerido en Google y Vercel**

```ruby
raise BetterAuth::Error, "CODE_VERIFIER_REQUIRED" if verifier.to_s.empty?
```

- **Step 3: Ejecutar pruebas focalizadas**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb -n /(railway_|google_and_vercel_require_code_verifier)/`
Expected: PASS.

- **Step 4: Commit de fixes**

```bash
git add packages/better_auth/lib/better_auth/social_providers/railway.rb packages/better_auth/lib/better_auth/social_providers/google.rb packages/better_auth/lib/better_auth/social_providers/vercel.rb packages/better_auth/test/better_auth/social_providers_test.rb
git commit -m "fix(social): align railway auth and pkce requirements with upstream"
```

### Task 6: Regresión integral y reporte final de paridad

**Files:**

- Modify: `docs/superpowers/plans/2026-04-29-social-providers-parity.md`
- Test: `packages/better_auth/test/better_auth/social_providers_test.rb`
- Test: `packages/better_auth/test/better_auth/routes/social_test.rb`
- **Step 1: Ejecutar suite social completa Ruby**

Run: `cd /Users/sebastiansala/projects/better-auth/packages/better_auth && bundle exec ruby -Itest test/better_auth/social_providers_test.rb && bundle exec ruby -Itest test/better_auth/routes/social_test.rb`
Expected: PASS sin regresiones.

- **Step 2: Recalcular % de paridad después de cambios**

```markdown
## Cálculo de % final
A final = 36/36 = 100%
B final = 24/24 = 100%
C final = 12/12 = 100%
Paridad final = (100 + 100 + 100) / 3 = 100%
```

- **Step 3: Registrar diferencias remanentes (si existen)**

```markdown
## Diferencias remanentes
- Si aparece una diferencia no portable a Ruby, documentar motivo técnico y cobertura compensatoria.
```

- **Step 4: Commit final de reporte**

```bash
git add docs/superpowers/plans/2026-04-29-social-providers-parity.md
git commit -m "docs(plan): close social providers parity report with before/after metrics"
```

## Supuestos y exclusiones Ruby

- Se asume upstream target `v1.6.9` en `upstream/` y que los tests Ruby se ejecutan con Minitest sin infraestructura externa adicional.
- Exclusión válida: diferencias de tipos/ergonomía entre TypeScript y Ruby (por ejemplo tipos estáticos, shapes exactos de interfaces) no se consideran gap funcional si el comportamiento observable en runtime coincide.
- Exclusión válida: hooks/contextos internos de upstream no expuestos en Ruby se cubren por pruebas de comportamiento en rutas y providers.

