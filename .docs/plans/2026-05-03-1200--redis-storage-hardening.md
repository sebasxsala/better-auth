# Redis storage hardening implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Endurecer `better_auth-redis-storage` validando opciones que controlamos en Ruby, alinear TTL numérico (`Numeric`), hacer `clear` seguro en Redis con muchas claves, documentar límites operativos (prefijo vacío, orden de claves, cluster), y ampliar pruebas sin inventar capas que dependan del comportamiento interno del cliente Redis salvo lo necesario.

**Architecture:** Cambios localizados en `BetterAuth::RedisStorage` (`initialize`, `prefix_key`, `coerce_ttl`, `clear`), tests en `packages/better_auth-redis-storage/test/`, documentación en `README.md` y entrada en `CHANGELOG.md`. Sin nuevo gem de dependencias; solo Redis estándar y la API pública actual.

**Tech Stack:** Ruby ≥ 3.2, gem `redis` 5.x, Minitest, Rake.

**Scope note (qué no entra y por qué):**

| Idea descartada | Motivo |
|-----------------|--------|
| Envolver todas las excepciones Redis en un tipo propio | YAGNI: Better Auth core no define contrato de errores para secondary storage; el cliente ya lanza errores útiles. |
| Tests automatizados contra Redis Cluster | Infra y comportamiento dependen del cliente/cluster; no reproducible en CI sin compose dedicado; la mitigación es documentación. |
| Corregir sub-second TTL para igualar ioredis al milisegundo | Redis `SETEX` usa segundos enteros; el gem Ruby también; paridad exacta con fracciones es ambigua y depende del cliente TS. |
| Prohibir por defecto `key_prefix: ""` sin flag | Rompe compatibilidad con README actual (“cadena vacía se respeta”); en su lugar advertencia fuerte en docs. |
| Pipeline masivo con UNLINK obligatorio | `UNLINK` es estándar pero cambia semántica respecto a `DEL` (async); chunking con `del` mantiene paridad razonable; opcional mencionar `UNLINK` en docs para datasets enormes. |

---

## File map

| File | Rol |
|------|-----|
| `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` | Validación `scan_count`, `prefix_key`, `coerce_ttl` ampliado, `clear` por lotes |
| `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb` | Tests unitarios nuevos y ajuste de orden de `list_keys` |
| `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb` | Al menos un caso `scan_count` con Redis real |
| `packages/better_auth-redis-storage/README.md` | Operaciones peligrosas, TTL, cluster, orden indefinido |
| `packages/better_auth-redis-storage/CHANGELOG.md` | Entrada bajo Unreleased |

---

### Task 1: Validar `scan_count` en `initialize`

**Files:**

- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` (`initialize`)
- Test: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`

- [x] **Step 1: Escribir test que falle**

```ruby
def test_scan_count_must_be_nil_or_positive_integer
  error = assert_raises(ArgumentError) do
    BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: 0)
  end
  assert_match(/scan_count/i, error.message)

  error = assert_raises(ArgumentError) do
    BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: -1)
  end
  assert_match(/scan_count/i, error.message)

  error = assert_raises(ArgumentError) do
    BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: "100")
  end
  assert_match(/scan_count/i, error.message)
end

def test_scan_count_accepts_positive_integer
  storage = BetterAuth::RedisStorage.new(client: FakeRedisClient.new, scan_count: 100)
  assert_equal 100, storage.scan_count
end

def test_scan_count_nil_uses_keys_not_scan
  client = FakeRedisClient.new
  storage = BetterAuth::RedisStorage.new(client: client, scan_count: nil)
  storage.set("a", "1")
  storage.list_keys
  assert_equal ["better-auth:*"], client.keys_calls
end
```

- [x] **Step 2: Ejecutar test esperando fallo**

Run (desde `packages/better_auth-redis-storage`):

```bash
bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n "/scan_count/"
```

Expected: FAIL (ArgumentError no raised or message mismatch).

- [x] **Step 3: Implementar validación**

En `initialize`, después de asignar `@key_prefix`:

```ruby
if !scan_count.nil? && !(scan_count.is_a?(Integer) && scan_count.positive?)
  raise ArgumentError, "scan_count must be nil or a positive Integer (hint: use 100..1000 for SCAN); got #{scan_count.inspect}"
end
@scan_count = scan_count
```

Asegurar que `build`, `redis_storage` y `redisStorage` sigan pasando `scan_count` igual.

- [x] **Step 4: Ejecutar tests del archivo**

```bash
bundle exec rake test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb
git commit -m "fix(redis-storage): validate scan_count is nil or positive Integer"
```

---

### Task 2: Rechazar claves lógicas `nil` en `prefix_key`

**Files:**

- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` (`prefix_key`)
- Test: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`

- [x] **Step 1: Test**

```ruby
def test_nil_logical_key_raises
  assert_raises(ArgumentError) { @storage.get(nil) }
  assert_raises(ArgumentError) { @storage.set(nil, "v") }
  assert_raises(ArgumentError) { @storage.delete(nil) }
end
```

- [x] **Step 2: Fallo**

```bash
bundle exec ruby -Itest test/better_auth/redis_storage_test.rb -n test_nil_logical_key_raises
```

Expected: FAIL.

- [x] **Step 3: Implementación**

Al inicio de `prefix_key`:

```ruby
def prefix_key(key)
  raise ArgumentError, "secondary storage key must not be nil" if key.nil?

  "#{key_prefix}#{key}"
end
```

- [x] **Step 4: `bundle exec rake test`**

- [ ] **Step 5: Commit**

```bash
git commit -m "fix(redis-storage): reject nil logical keys"
```

---

### Task 3: Unificar coerción TTL para `Numeric` (p. ej. `BigDecimal`)

**Files:**

- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` (`coerce_ttl`)
- Test: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`

- [x] **Step 1: Test**

```ruby

def test_set_with_bigdecimal_ttl_uses_setex
  ttl = BigDecimal("120")
  @storage.set("bd-ttl", "payload", ttl)

  assert_equal [["better-auth:bd-ttl", 120, "payload"]], @client.setex_calls
end

def test_non_finite_numeric_ttl_falls_back_to_set
  @storage.set("nan-ttl", "payload", Float::NAN)

  assert_equal [["better-auth:nan-ttl", "payload"]], @client.set_calls
end
```

Ruby-specific adaptation: the implemented unit test uses `Rational` instead of
`BigDecimal` because `bigdecimal` is not available in the current bundle without
adding a new dependency. This still exercises the intended non-Integer
`Numeric` coercion path.

- [x] **Step 2: Implementación de `coerce_ttl`**

Reemplazar el método por una versión que trate `Integer` y `Float` como hoy, `String` como hoy, y **`Numeric`** restante vía `to_f` + `finite?` + `positive?` → `to_i`:

```ruby
def coerce_ttl(ttl)
  numeric =
    case ttl
    when nil
      nil
    when Integer
      ttl
    when Float
      ttl.finite? ? ttl : nil
    when String
      Integer(ttl, exception: false)
    when Numeric
      f = ttl.to_f
      f.finite? && f.positive? ? f : nil
    else
      nil
    end

  return nil if numeric.nil?
  return nil unless numeric.is_a?(Numeric) && numeric.respond_to?(:positive?) && numeric.positive?

  numeric.is_a?(Integer) ? numeric : numeric.to_i
end
```

Revisar tests existentes `test_set_with_float_positive_ttl_truncates_to_integer` y `test_set_falls_back_to_plain_set_for_non_numeric_or_negative_ttl` para que sigan pasando (ajustar solo si el comportamiento de `Float` negativo o `0.0` cambia; `0.0.to_i` es 0 → no `setex`).

- [x] **Step 3: `bundle exec rake test`**

- [ ] **Step 4: Commit**

```bash
git commit -m "fix(redis-storage): coerce BigDecimal and other Numeric TTLs"
```

---

### Task 4: `clear` con borrado por lotes

**Files:**

- Modify: `packages/better_auth-redis-storage/lib/better_auth/redis_storage.rb` (`clear`, constante de tamaño de lote)
- Test: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`

- [x] **Step 1: Test con fake que registra llamadas `del`**

Extender `FakeRedisClient` para acumular cada invocación `del` (ya lo hace). Añadir:

```ruby
def test_clear_deletes_in_chunks_when_many_keys
  client = FakeRedisClient.new
  storage = BetterAuth::RedisStorage.new(client: client)
  600.times { |i| storage.set("k#{i}", "v") }

  storage.clear

  assert_operator client.del_calls.length, :>=, 2
  assert_equal 0, client.data.keys.count { |k| k.start_with?("better-auth:") }
end
```

Añadir constante en la clase, por ejemplo `DELETE_CHUNK_SIZE = 500`, y en `clear`:

```ruby
def clear
  keys = storage_keys
  return nil if keys.empty?

  keys.each_slice(RedisStorage::DELETE_CHUNK_SIZE) { |chunk| client.del(*chunk) }
  nil
end
```

Documentar en README el tamaño del lote.

- [x] **Step 2: Implementar y ejecutar `bundle exec rake test`**

- [ ] **Step 3: Commit**

```bash
git commit -m "fix(redis-storage): chunk delete in clear to avoid huge argv"
```

---

### Task 5: Ajustar test de orden de `list_keys` (no asumir orden de Redis)

**Files:**

- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_test.rb`

- [x] **Step 1: Cambiar `test_list_keys_preserves_public_write_order`**

Sustituir la aserción de orden fijo por igualdad de conjunto:

```ruby
def test_list_keys_returns_all_logical_keys
  @storage.set("first", "one")
  @storage.set("second", "two")
  @storage.set("third", "three")

  assert_equal ["first", "second", "third"].sort, @storage.list_keys.sort
end
```

- [x] **Step 2: `bundle exec rake test`**

- [ ] **Step 3: Commit**

```bash
git commit -m "test(redis-storage): do not assume KEYS ordering"
```

---

### Task 6: Integración real con `scan_count`

**Files:**

- Modify: `packages/better_auth-redis-storage/test/better_auth/redis_storage_integration_test.rb`

- [x] **Step 1: Test bajo `REDIS_INTEGRATION=1`**

```ruby
def test_scan_count_round_trip_lists_keys
  storage = BetterAuth::RedisStorage.new(
    client: @client,
    key_prefix: "#{@prefix_root}:scan:",
    scan_count: 50
  )
  storage.clear
  storage.set("x", "1")
  storage.set("y", "2")

  keys = storage.list_keys.sort

  assert_equal ["x", "y"], keys
ensure
  storage&.clear
end
```

- [x] **Step 2: Ejecutar con Redis**

```bash
REDIS_INTEGRATION=1 bundle exec ruby -Itest test/better_auth/redis_storage_integration_test.rb -n test_scan_count_round_trip_lists_keys
```

- [ ] **Step 3: Commit**

```bash
git commit -m "test(redis-storage): integration coverage for scan_count"
```

---

### Task 7: Documentación y changelog

**Files:**

- Modify: `packages/better_auth-redis-storage/README.md`
- Modify: `packages/better_auth-redis-storage/CHANGELOG.md`

- [x] **Step 1: README — secciones concretas**

Añadir o ampliar:

1. **Prefijo vacío:** un párrafo explícito de que `key_prefix: ""` hace que `KEYS`/`SCAN` usen `*` y que `clear` borre **todas** las claves de la base seleccionada; recomendar prefijos únicos por app.

2. **`list_keys`:** el orden no está garantizado (comportamiento de Redis); usar `.sort` si se necesita orden estable.

3. **TTL:** tabla ampliada: cualquier `Numeric` positivo finito → `setex` con segundos enteros vía truncamiento (`to_i`); `Float::NAN` / infinito → `SET` sin expiración.

4. **Cluster:** advertencia breve: en Cluster, operaciones multi-key deben compartir slot; este adaptador no ejecuta `SCAN` por nodo; uso bajo propio riesgo con prefijos/hash tags Redis.

5. **`clear`:** borrado en lotes de `DELETE_CHUNK_SIZE` claves por llamada a `del`.

- [x] **Step 2: CHANGELOG (Unreleased)**

```markdown
- Validate `scan_count` (nil or positive Integer only).
- Reject nil logical keys for get/set/delete/list_keys/clear paths that use `prefix_key`.
- Coerce non-Integer `Numeric` TTLs (e.g. BigDecimal) for SETEX.
- Chunk `clear` deletes to avoid oversized DEL commands.
- Document operational caveats (empty prefix, key order, cluster).
```

- [ ] **Step 3: Commit**

```bash
git commit -m "docs(redis-storage): operational caveats and CHANGELOG"
```

---

## Self-review (cobertura)

| Hallazgo original | Task |
|-------------------|------|
| `scan_count` truthiness (0, negativo, tipos) | Task 1 |
| `nil` key → colisión bajo prefijo | Task 2 |
| `BigDecimal` / TTL no contemplado | Task 3 |
| `del(*keys)` masivo | Task 4 |
| Test asume orden de `KEYS` | Task 5 |
| Sin integración real para `SCAN` | Task 6 |
| Docs: prefijo vacío, orden, cluster, TTL | Task 7 |

**Placeholder scan:** no quedan TBD; cada paso tiene comando o código.

**Consistencia:** `DELETE_CHUNK_SIZE` debe ser la misma constante referenciada en README y en `clear`.

---

## Ejecución

**Plan guardado en:** `.docs/plans/2026-05-03-1200--redis-storage-hardening.md`

**Opciones:**

1. **Subagent-Driven (recomendado)** — Un subagente por task, revisión entre tareas; usar skill `subagent-driven-development`.
2. **Inline** — Ejecutar en esta sesión con checkpoints; usar skill `executing-plans`.

**¿Cuál prefieres?**
