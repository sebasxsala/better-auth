# SCIM: rendimiento, paridad upstream y comparación segura de tokens

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reducir coste de `GET /scim/v2/Users`, alinear el comportamiento de PATCH en `givenName`/`familyName` con `upstream/packages/scim/src/patch-operations.ts`, y endurecer la validación de tokens SCIM en `default_scim` frente a comparaciones por tiempo.

**Architecture:** Se mantiene la lógica en `BetterAuth::Plugins` (`routes.rb`, `middlewares.rb`, `patch_operations.rb`, `mappings.rb`). La lista de usuarios dejará de usar `list_users` sin filtro; pasará a consultar solo usuarios cuyo `id` esté en los `account` del `providerId`, con filtro opcional `email eq` derivado de `userName eq`, y orden estable por email. El middleware usará `BetterAuth::Crypto.constant_time_compare` cuando ambos secretos tengan la misma longitud; si no, se rechaza sin comparación byte a byte.

**Tech Stack:** Ruby 3.2+, gem `better_auth` (Minitest, StandardRB), paquete `packages/better_auth-scim`.

---

## Alcance y exclusiones (por qué no van en este plan)

| Exclusión | Motivo |
|-----------|--------|
| Paginación RFC (`startIndex`, `count`) | Funcionalidad grande; ningún bug lógico en el código actual respecto a upstream (upstream tampoco pagina la lista). Mejor plan aparte si se prioriza certificación IdP. |
| Recurso **Group**, **Bulk**, filtros `co`/`sw`/… | No están en upstream actual; ampliación de producto, no corrección del paquete Ruby. |
| Cambiar `emailVerified` en alta SCIM | Implementado después de aprobación explícita en el plan cross-cutting: Ruby ya no fuerza `emailVerified: true`; nuevos usuarios SCIM conservan el default core/upstream (`false`). |
| Sustituir `delete_user` por solo desvincular cuenta | Cambio de modelo de datos y semántica SCIM; requiere decisión de producto y cambios en adaptadores. |
| Índice único compuesto `(providerId, accountId)` en el esquema core | Viviría en `better_auth` y migraciones por adaptador; fuera del alcance del gem SCIM. Se documenta como recomendación operativa. |
| Hardening exhaustivo de timing en todos los adaptadores de token | `scim_token_matches?` ya re-hash para `hashed`; el foco aquí es el ramo `default_scim` que compara en claro. |

---

## Mapa de archivos

| Archivo | Responsabilidad |
|---------|-----------------|
| `packages/better_auth-scim/lib/better_auth/scim/routes.rb` | `list_scim_users_endpoint`: consultas acotadas, respuesta vacía temprana, orden estable. |
| `packages/better_auth-scim/lib/better_auth/scim/middlewares.rb` | Comparación constante del token en `default_scim`. |
| `packages/better_auth-scim/lib/better_auth/scim/patch_operations.rb` | Rutas `/name/givenName` y `/name/familyName` alineadas con upstream. |
| `packages/better_auth-scim/lib/better_auth/scim/mappings.rb` | Helpers auxiliares si hace falta para no duplicar lógica (solo si reduce complejidad). |
| `packages/better_auth-scim/test/better_auth/scim/scim_users_test.rb` | Orden determinista en listados; caso vacío con filtro. |
| `packages/better_auth-scim/test/better_auth/scim/scim_patch_test.rb` | Expectativas para nombres de ≥3 partes si aplica; regresión replace/add. |
| `packages/better_auth-scim/README.md` | Breve “Production notes”: índice único recomendado en `accounts`. |

---

### Task 1: Lista SCIM acotada al proveedor + orden estable

**Files:**
- Modify: `packages/better_auth-scim/lib/better_auth/scim/routes.rb` (`scim_list_users_endpoint` y helpers locales si se extraen métodos privados `module_function` en el mismo archivo)
- Test: `packages/better_auth-scim/test/better_auth/scim/scim_users_test.rb`

**Comportamiento objetivo (espejo de `listSCIMUsers` en `upstream/packages/scim/src/routes.ts`):**

1. Cargar `accounts` con `providerId` igual al del token (sin cambio).
2. Si no hay `account`, devolver listado vacío con `totalResults: 0`, `itemsPerPage: 0`, `startIndex: 1`, `Resources: []` (igual que upstream `emptyListResponse`).
3. Calcular `account_user_ids` a partir de `accounts`.
4. Si hay `organizationId`, cargar `member` con `organizationId` + `userId IN account_user_ids`; si ningún miembro, listado vacío.
5. Construir `where` para `user`: `[{ field: "id", value: <ids finales>, operator: "in" }]`.
6. Si hay query `filter`, usar `scim_parse_filter` (ya lanza si es inválido). Añadir `{ field: "email", value: <valor en minúsculas>, operator: "eq" }` porque `userName` en SCIM mapea a `email` (como `SCIMUserAttributes` en upstream).
7. Obtener usuarios con `ctx.context.internal_adapter.list_users(where: where, sort_by: { field: "email", direction: "asc" })` (el adaptador interno ya delega en `find_many` con `sort_by`).
8. Construir `Resources`: indexar `accounts` por `userId` en un `Hash` para evitar `find` repetido por usuario.
9. Mantener `schemas`, `totalResults`, `itemsPerPage`, `startIndex` coherentes con los tests existentes.

- [x] **Step 1: Escribir test que falle (orden determinista)**

En `scim_users_test.rb`, añadir un test que cree dos usuarios y espere que `list_scim_users` devuelva `Resources` ordenados por `userName` (email) ascendente, independientemente del orden de creación. Opcional: stub no disponible; confiar en orden explícito del endpoint tras el cambio.

```ruby
def test_scim_list_users_orders_by_user_name
  auth = build_auth
  cookie = sign_up_cookie(auth)
  token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "sort-test"}).fetch(:scimToken)
  headers = bearer(token)

  auth.api.create_scim_user(headers: headers, body: {userName: "zebra@example.com"})
  auth.api.create_scim_user(headers: headers, body: {userName: "alpha@example.com"})

  listed = auth.api.list_scim_users(headers: headers)
  names = listed.fetch(:Resources).map { |u| u.fetch(:userName) }
  assert_equal %w[alpha@example.com zebra@example.com], names
end
```

- [x] **Step 2: Ejecutar test y comprobar fallo**

Run:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-scim && bundle exec ruby -Itest test/better_auth/scim/scim_users_test.rb -n test_scim_list_users_orders_by_user_name
```

Expected: FAIL (orden actual no garantizado o distinto).

- [x] **Step 3: Implementar refactor en `routes.rb`**

Reemplazar el cuerpo de `scim_list_users_endpoint` que hoy hace `list_users` global y filtra en memoria por algo equivalente a:

```ruby
# Pseudocódigo orientativo — integrar con el estilo existente del archivo
provider = ctx.context.scim_provider
accounts = ctx.context.adapter.find_many(model: "account", where: [{field: "providerId", value: provider.fetch("providerId")}])
account_user_ids = accounts.map { |a| a.fetch("userId") }.uniq

if account_user_ids.empty?
  return ctx.json({
    schemas: [SCIM_LIST_RESPONSE_SCHEMA],
    totalResults: 0,
    itemsPerPage: 0,
    startIndex: 1,
    Resources: []
  })
end

user_ids = account_user_ids
if provider["organizationId"]
  members = ctx.context.adapter.find_many(
    model: "member",
    where: [
      {field: "organizationId", value: provider.fetch("organizationId")},
      {field: "userId", value: user_ids, operator: "in"}
    ]
  )
  member_ids = members.map { |m| m.fetch("userId") }.uniq
  if member_ids.empty?
    return ctx.json({
      schemas: [SCIM_LIST_RESPONSE_SCHEMA],
      totalResults: 0,
      itemsPerPage: 0,
      startIndex: 1,
      Resources: []
    })
  end
  user_ids = member_ids
end

where = [{field: "id", value: user_ids, operator: "in"}]
if ctx.query[:filter] || ctx.query["filter"]
  _, filter_value = scim_parse_filter(ctx.query[:filter] || ctx.query["filter"])
  where << {field: "email", value: filter_value.to_s.downcase, operator: "eq"}
end

users = ctx.context.internal_adapter.list_users(
  where: where,
  sort_by: {field: "email", direction: "asc"}
)

accounts_by_user = accounts.each_with_object({}) { |a, h| h[a.fetch("userId")] = a }
resources = users.map { |user| scim_user_resource(user, accounts_by_user[user.fetch("id")], ctx.context.base_url) }

ctx.json({
  schemas: [SCIM_LIST_RESPONSE_SCHEMA],
  totalResults: resources.length,
  itemsPerPage: resources.length,
  startIndex: 1,
  Resources: resources
})
```

Ajustar nombres de helpers (`scim_param`, etc.) y hashes según convención del archivo.

- [x] **Step 4: Ejecutar suite SCIM**

Run:

```bash
cd /Users/sebastiansala/projects/better-auth/packages/better_auth-scim && bundle exec rake test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/sebastiansala/projects/better-auth
git add packages/better_auth-scim/lib/better_auth/scim/routes.rb packages/better_auth-scim/test/better_auth/scim/scim_users_test.rb
git commit -m "perf(scim): scope list users to provider accounts and sort by email"
```

---

### Task 2: Comparación en tiempo constante del token en `default_scim`

**Files:**
- Modify: `packages/better_auth-scim/lib/better_auth/scim/middlewares.rb`
- Test: nuevo archivo o ampliar `test/better_auth/scim/scim_users_test.rb` / `scim_management_test.rb` con caso `default_scim`

- [x] **Step 1: Test de regresión**

Con `build_auth(default_scim: [{providerId: "p", scimToken: "short"}])`, una petición con Bearer codificado correctamente debe 401 si el token literal no coincide (ya cubierto). Añadir aserción de que usuario válido sigue funcionando. Opcional: test que documente que longitudes distintas no disparan `fixed_length_secure_compare` (no debe lanzar).

```ruby
def test_scim_default_provider_rejects_wrong_token_length_safely
  token_ok = Base64.urlsafe_encode64("secret-token:p", padding: false)
  token_bad = Base64.urlsafe_encode64("different-length-xx:p", padding: false)
  auth = build_auth(default_scim: [{providerId: "p", scimToken: "secret-token"}])

  auth.api.create_scim_user(headers: bearer(token_ok), body: {userName: "ok@example.com"})

  assert_raises(BetterAuth::APIError) do
    auth.api.create_scim_user(headers: bearer(token_bad), body: {userName: "no@example.com"})
  end
end
```

- [x] **Step 2: Implementar**

En `scim_auth_middleware`, donde hoy está:

```ruby
raise scim_error("UNAUTHORIZED", "Invalid SCIM token") unless provider.fetch("scimToken") == token
```

sustituir por (requiere `Crypto` del core, ya disponible vía `better_auth`):

```ruby
stored = provider.fetch("scimToken").to_s
unless stored.bytesize == token.to_s.bytesize && BetterAuth::Crypto.constant_time_compare(stored, token.to_s)
  raise scim_error("UNAUTHORIZED", "Invalid SCIM token")
end
```

No usar `constant_time_compare` si las longitudes difieren (la API devuelve `false` sin comparar, lo cual es correcto).

- [x] **Step 3: `bundle exec rake test` en el paquete scim**

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-scim/lib/better_auth/scim/middlewares.rb packages/better_auth-scim/test/better_auth/scim/scim_users_test.rb
git commit -m "security(scim): constant-time compare for default_scim bearer tokens"
```

---

### Task 3: Paridad upstream en PATCH `givenName` / `familyName`

**Files:**
- Modify: `packages/better_auth-scim/lib/better_auth/scim/patch_operations.rb`
- Reference: `upstream/packages/scim/src/patch-operations.ts` (`givenName`, `familyName`, `getUserFullName`)
- Modify: `packages/better_auth-scim/lib/better_auth/scim/mappings.rb` solo si centralizas `getUserFullName` equivalente
- Test: `packages/better_auth-scim/test/better_auth/scim/scim_patch_test.rb`

**Lógica upstream a reproducir:**

- Al aplicar **givenName**: `familyName` actual = todo lo que sigue al primer espacio del nombre compuesto actual (`currentName.split(" ").slice(1).join(" ").trim()`).
- Al aplicar **familyName**: `givenName` actual = todo salvo la última palabra (`slice(0, -1).join(" ") || currentName`).

El nombre “actual” durante el patch debe preferir `update[:name]` si ya se fue mutando en la misma petición, igual que `resources.user.name` en TypeScript.

- [x] **Step 1: Test con nombre de tres segmentos**

Crear usuario con `name: {formatted: "Anne Marie Smith"}` y aplicar PATCH replace `givenName` → `"X"`; documentar expectativa según upstream (familia subyacente `Marie Smith`).

```ruby
def test_scim_patch_given_name_three_word_display_name_matches_upstream_split
  auth = build_auth
  cookie = sign_up_cookie(auth)
  token = auth.api.generate_scim_token(headers: {"cookie" => cookie}, body: {providerId: "okta"}).fetch(:scimToken)
  headers = bearer(token)
  created = auth.api.create_scim_user(
    headers: headers,
    body: {userName: "three@example.com", name: {formatted: "Anne Marie Smith"}}
  )

  auth.api.patch_scim_user(
    headers: headers,
    params: {userId: created.fetch(:id)},
    body: {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{op: "replace", path: "/name/givenName", value: "Pat"}]
    },
    return_status: true
  )
  patched = auth.api.get_scim_user(headers: headers, params: {userId: created.fetch(:id)})
  # Valor esperado tras alinear con upstream (getUserFullName con given Pat y family "Marie Smith"):
  assert_equal "Pat Marie Smith", patched.fetch(:displayName)
end
```

(Ajustar la aserción final si al portar `getUserFullName` el resultado difiere en espacios; la fuente de verdad es el TypeScript.)

- [x] **Step 2: Implementar en `scim_apply_patch_path!`**

Ruby note: after comparing with `upstream/packages/scim/src/patch-operations.ts`, the existing `scim_given_name` / `scim_family_name` behavior already matched the upstream split semantics for the planned three-segment cases. I added the regression test and left production code unchanged.

Sustituir el uso de `scim_given_name`/`scim_family_name` actuales en las ramas `/name/givenName` y `/name/familyName` por funciones que implementen exactamente los cortes de `patch-operations.ts`, combinando con `scim_full_name` / `getUserPrimaryEmail` ya existentes donde corresponda.

- [x] **Step 3: Ejecutar `bundle exec rake test`**

Actualizar tests previos que dependían del algoritmo antiguo solo si las expectativas ya no coinciden con upstream.

- [ ] **Step 4: Commit**

```bash
git add packages/better_auth-scim/lib/better_auth/scim/patch_operations.rb packages/better_auth-scim/test/better_auth/scim/scim_patch_test.rb
git commit -m "fix(scim): align PATCH givenName/familyName splitting with upstream"
```

---

### Task 4: Documentación operativa (índice único recomendado)

**Files:**
- Modify: `packages/better_auth-scim/README.md`

- [x] **Step 1: Añadir sección breve**

```markdown
## Production recommendations

- En la tabla de cuentas (`accounts` o el nombre configurado), se recomienda un **índice único** compuesto por `(providerId, accountId)` para evitar cuentas SCIM duplicadas bajo concurrencia. El gem no crea esta restricción automáticamente porque depende del motor SQL y de las migraciones de tu aplicación.
```

- [ ] **Step 2: Commit**

```bash
git add packages/better_auth-scim/README.md
git commit -m "docs(scim): recommend unique index on provider and account id"
```

---

## Self-review (checklist interna)

1. **Cobertura del análisis previo:** Rendimiento lista ✓; comparación token default ✓; paridad PATCH nombres ✓; documentación índice ✓. Excluidos explícitamente: paginación, grupos, bulk, delete parcial, índice en core. `emailVerified` fue alineado con upstream en un seguimiento posterior.
2. **Placeholders:** Sin TBD; los fragmentos de código son implementables (ajustar al estilo del archivo).
3. **Consistencia:** `list_users`/`where`/`sort_by` coincide con `InternalAdapter` y adaptadores memory/sql con operador `in`.

---

**Plan complete and saved to `.docs/plans/2026-05-03-2200--scim-performance-parity-security.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — Fresh subagent per task, review between tasks.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
