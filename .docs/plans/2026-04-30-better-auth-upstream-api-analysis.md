# Better Auth Upstream API Analysis (v1.6.9)

## 1. Clase Principal e Inicialización

### Punto de Entrada

La función principal es **`betterAuth`** exportada desde:
- **`better-auth`**: `packages/better-auth/src/auth/full.ts` (modo completo con Kysely)
- **`better-auth/minimal`**: `packages/better-auth/src/auth/minimal.ts` (modo minimal sin Kysely)

### Función `createBetterAuth`

Archivo: `packages/better-auth/src/auth/base.ts`

Esta es la fábrica central que crea el objeto `Auth`. Recibe:
- `options: BetterAuthOptions`
- `initFn: (options) => Promise<AuthContext>`

Retorna un objeto `Auth<Options>` con estas propiedades:

| Propiedad | Tipo | Descripción |
|-----------|------|-------------|
| `handler` | `(request: Request) => Promise<Response>` | Handler HTTP para frameworks/edge runtimes |
| `api` | `InferAPI<...>` | Objeto con TODOS los endpoints disponibles para llamadas directas server-side |
| `options` | `Options` | Opciones originales pasadas a betterAuth |
| `$context` | `Promise<AuthContext>` | Contexto de auth resuelto (incluye adapter, secret, etc.) |
| `$ERROR_CODES` | `Record<string, {code, message}>` | Códigos de error base + de plugins |
| `$Infer` | Tipos inferidos | Tipos de Session, User, etc. inferidos de options |

### Construcción de `api`

El `api` se construye en `packages/better-auth/src/api/index.ts` mediante:

```typescript
const { api } = getEndpoints(authContext, options);
```

`getEndpoints`:
1. Recolecta endpoints base (auth core)
2. Recolecta endpoints de todos los plugins (`plugin.endpoints`)
3. Combina todo en un solo objeto
4. Pasa por `toAuthEndpoints(endpoints, ctx)` que envuelve cada endpoint con:
   - Resolución de contexto dinámico (baseURL)
   - Ejecución de before/after hooks (globales y de plugins)
   - Manejo de `asResponse`, `returnHeaders`, `returnStatus`
   - Instrumentación con spans OpenTelemetry

---

## 2. Endpoints Base (Core API)

Estos están definidos en `packages/better-auth/src/api/routes/` y están disponibles SIEMPRE en `auth.api`.

### 2.1 Autenticación (Sign In / Sign Up / Sign Out)

#### `signInSocial`
- **Ruta HTTP**: `POST /sign-in/social`
- **Parámetros (body)**:
  - `provider: string` (enum de SocialProviderList)
  - `callbackURL?: string`
  - `newUserCallbackURL?: string`
  - `errorCallbackURL?: string`
  - `disableRedirect?: boolean`
  - `idToken?: { token, nonce?, accessToken?, refreshToken?, expiresAt?, user? }`
  - `scopes?: string[]`
  - `requestSignUp?: boolean`
  - `loginHint?: string`
  - `additionalData?: Record<string, any>`
- **Comportamiento**: Inicia flujo OAuth2 (redirección) o autentica directamente con idToken
- **Retorno**: `{ redirect: boolean, url: string }` o `{ redirect: false, token, user }`

#### `signInEmail`
- **Ruta HTTP**: `POST /sign-in/email`
- **Parámetros (body)**:
  - `email: string`
  - `password: string`
  - `callbackURL?: string`
  - `rememberMe?: boolean` (default: true)
- **Middleware**: `formCsrfMiddleware`
- **Comportamiento**: Valida email/password, crea sesión, setea cookie. Requiere `emailAndPassword.enabled`
- **Retorno**: `{ redirect: boolean, token: string, url?, user }`

#### `signUpEmail`
- **Ruta HTTP**: `POST /sign-up/email`
- **Parámetros (body)**:
  - `name: string`
  - `email: string`
  - `password: string`
  - `image?: string`
  - `callbackURL?: string`
  - `rememberMe?: boolean`
  - Campos adicionales dinámicos según `user.additionalFields`
- **Middleware**: `formCsrfMiddleware`
- **Comportamiento**: Crea usuario + cuenta credential + sesión. Envía email de verificación si está configurado
- **Retorno**: `{ token: string | null, user }`

#### `signOut`
- **Ruta HTTP**: `POST /sign-out`
- **Parámetros**: Requiere headers (cookies)
- **Comportamiento**: Borra sesión de DB, elimina cookies
- **Retorno**: `{ success: boolean }`

---

### 2.2 Sesión

#### `getSession`
- **Ruta HTTP**: `GET|POST /get-session`
- **Parámetros (query)**:
  - `disableCookieCache?: boolean`
  - `disableRefresh?: boolean`
- **Requiere headers**: Sí
- **Comportamiento**:
  - Lee cookie `session_token`
  - Si existe `session_data` cookie cache y está vigente, retorna desde cache
  - Si no, busca en DB
  - Throttling de actualización: solo actualiza DB si `updateAge` ha pasado
  - Soporta `deferSessionRefresh`: POST permite refresh, GET solo lectura con flag `needsRefresh`
- **Retorno**: `{ session, user } | null`

#### `listSessions`
- **Ruta HTTP**: `GET /list-sessions`
- **Middleware**: `sessionMiddleware`
- **Comportamiento**: Lista sesiones activas del usuario autenticado
- **Retorno**: `Session[]`

#### `revokeSession`
- **Ruta HTTP**: `POST /revoke-session`
- **Parámetros (body)**: `{ token: string }`
- **Middleware**: `sensitiveSessionMiddleware` (ignora cookie cache)
- **Comportamiento**: Revoca una sesión específica si pertenece al usuario actual

#### `revokeSessions`
- **Ruta HTTP**: `POST /revoke-sessions`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**: Revoca TODAS las sesiones del usuario

#### `revokeOtherSessions`
- **Ruta HTTP**: `POST /revoke-other-sessions`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**: Revoca todas las sesiones excepto la actual

---

### 2.3 Cuentas y OAuth

#### `listUserAccounts`
- **Ruta HTTP**: `GET /list-accounts`
- **Middleware**: `sessionMiddleware`
- **Retorno**: Array de cuentas con `providerId`, `accountId`, `scopes[]`

#### `linkSocialAccount`
- **Ruta HTTP**: `POST /link-social`
- **Parámetros (body)**:
  - `provider: string`
  - `callbackURL?: string`
  - `idToken?: { token, nonce?, accessToken?, refreshToken?, scopes? }`
  - `requestSignUp?: boolean`
  - `scopes?: string[]`
  - `errorCallbackURL?: string`
  - `disableRedirect?: boolean`
  - `additionalData?: Record<string, any>`
- **Middleware**: `sessionMiddleware`
- **Comportamiento**: Inicia flujo OAuth para vincular cuenta o usa idToken directamente

#### `unlinkAccount`
- **Ruta HTTP**: `POST /unlink-account`
- **Parámetros (body)**: `{ providerId: string, accountId?: string }`
- **Middleware**: `freshSessionMiddleware`
- **Comportamiento**: Desvincula cuenta social. No permite desvincular la última cuenta a menos que `allowUnlinkingAll` esté habilitado

#### `getAccessToken`
- **Ruta HTTP**: `POST /get-access-token`
- **Parámetros (body)**: `{ providerId: string, accountId?: string, userId?: string }`
- **Comportamiento**: Obtiene access token válido, haciendo refresh si es necesario. Lee de cookie de cuenta si existe

#### `refreshToken`
- **Ruta HTTP**: `POST /refresh-token`
- **Parámetros (body)**: `{ providerId: string, accountId?: string, userId?: string }`
- **Comportamiento**: Fuerza refresh del token OAuth2 y actualiza DB

#### `accountInfo`
- **Ruta HTTP**: `GET /account-info`
- **Query**: `{ accountId?: string }`
- **Middleware**: `sessionMiddleware`
- **Comportamiento**: Obtiene info del usuario desde el provider usando el access token

#### `callbackOAuth`
- **Ruta HTTP**: `GET|POST /callback/:id`
- **Parámetros (query/body)**: `{ code?, error?, state?, error_description?, device_id?, user? }`
- **Comportamiento**: Callback de OAuth2. Valida código, obtiene tokens, crea/linkea usuario, setea sesión, redirige

---

### 2.4 Verificación de Email

#### `sendVerificationEmail`
- **Ruta HTTP**: `POST /send-verification-email`
- **Parámetros (body)**: `{ email: string, callbackURL?: string }`
- **Comportamiento**: Genera JWT y envía email usando `options.emailVerification.sendVerificationEmail`

#### `verifyEmail`
- **Ruta HTTP**: `GET /verify-email`
- **Query**: `{ token: string, callbackURL?: string }`
- **Comportamiento**:
  - Verifica JWT
  - Soporta flujo de cambio de email (two-step: confirmation -> verification)
  - Actualiza `emailVerified: true`
  - Auto-sign-in si está configurado
  - Redirige a callbackURL

---

### 2.5 Password

#### `requestPasswordReset`
- **Ruta HTTP**: `POST /request-password-reset`
- **Parámetros (body)**: `{ email: string, redirectTo?: string }`
- **Middleware**: `originCheck(redirectTo)`
- **Comportamiento**: Crea token de verificación y envía email usando `sendResetPassword`

#### `requestPasswordResetCallback`
- **Ruta HTTP**: `GET /reset-password/:token`
- **Query**: `{ callbackURL: string }`
- **Comportamiento**: Valida token y redirige a callbackURL con `?token=VALID_TOKEN`

#### `resetPassword`
- **Ruta HTTP**: `POST /reset-password`
- **Parámetros**:
  - Body: `{ newPassword: string, token?: string }`
  - Query: `{ token?: string }`
- **Comportamiento**: Valida token, hashea nueva password, actualiza/crea cuenta credential. Opcionalmente revoca sesiones

#### `verifyPassword`
- **Ruta HTTP**: `POST /verify-password`
- **Parámetros (body)**: `{ password: string }`
- **Middleware**: `sensitiveSessionMiddleware`
- **Scope**: `server` (no expuesto a cliente)
- **Comportamiento**: Verifica que la password actual sea correcta

---

### 2.6 Usuario y Sesión (Update)

#### `updateUser`
- **Ruta HTTP**: `POST /update-user`
- **Parámetros (body)**: `{ name?, image?, ...additionalFields }`
- **Middleware**: `sessionMiddleware`
- **Restricciones**: No permite cambiar email directamente
- **Comportamiento**: Actualiza usuario y refresca cookie de sesión

#### `updateSession`
- **Ruta HTTP**: `POST /update-session`
- **Parámetros (body)**: `Record<string, any>` (campos adicionales de sesión)
- **Middleware**: `sessionMiddleware`
- **Comportamiento**: Actualiza campos adicionales de la sesión en DB y cookie

#### `changePassword`
- **Ruta HTTP**: `POST /change-password`
- **Parámetros (body)**: `{ newPassword: string, currentPassword: string, revokeOtherSessions?: boolean }`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**: Verifica password actual, actualiza hash. Si `revokeOtherSessions`, crea nueva sesión y revoca las demás

#### `setPassword`
- **Ruta HTTP**: `POST` (path virtual)
- **Parámetros (body)**: `{ newPassword: string }`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**: Establece password para usuarios sin password (ej: OAuth-only). Error si ya tiene password

#### `changeEmail`
- **Ruta HTTP**: `POST /change-email`
- **Parámetros (body)**: `{ newEmail: string, callbackURL?: string }`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**:
  - Si email no verificado y `updateEmailWithoutVerification`: actualiza directamente
  - Si verificado y `sendChangeEmailConfirmation`: envía email de confirmación
  - Sino: envía verificación de dos pasos

#### `deleteUser`
- **Ruta HTTP**: `POST /delete-user`
- **Parámetros (body)**: `{ callbackURL?, password?, token? }`
- **Middleware**: `sensitiveSessionMiddleware`
- **Comportamiento**:
  - Requiere `user.deleteUser.enabled`
  - Si `password` proporcionado: verifica password
  - Si `token` proporcionado: llama a deleteUserCallback
  - Si `sendDeleteAccountVerification`: envía email con token
  - Sino: verifica sesión fresh y elimina

#### `deleteUserCallback`
- **Ruta HTTP**: `GET /delete-user/callback`
- **Query**: `{ token: string, callbackURL?: string }`
- **Comportamiento**: Valida token de eliminación y elimina usuario + sesiones + cuentas

---

### 2.7 Utilidades

#### `ok`
- **Ruta HTTP**: `GET /ok`
- **Retorno**: `{ ok: true }`
- **Uso**: Health check

#### `error`
- **Ruta HTTP**: `GET /error`
- **Query**: `{ error?: string, error_description? }`
- **Comportamiento**: Renderiza página HTML de error o redirige a `onAPIError.errorURL`

---

## 3. Endpoints de Plugins

Los plugins registran sus endpoints en `plugin.endpoints`, que se mergean en `auth.api`.

### 3.1 Admin Plugin (`admin`)

Archivo: `packages/better-auth/src/plugins/admin/admin.ts`

| Endpoint | Ruta HTTP | Método | Descripción |
|----------|-----------|--------|-------------|
| `setRole` | `/admin/set-role` | POST | Asigna rol a usuario |
| `getUser` | `/admin/get-user` | GET | Obtiene usuario por ID/email |
| `createUser` | `/admin/create-user` | POST | Crea usuario admin |
| `adminUpdateUser` | `/admin/update-user` | POST | Actualiza usuario |
| `listUsers` | `/admin/list-users` | GET | Lista usuarios con paginación/filtros |
| `listUserSessions` | `/admin/list-user-sessions` | GET | Lista sesiones de un usuario |
| `unbanUser` | `/admin/unban-user` | POST | Desbloquea usuario |
| `banUser` | `/admin/ban-user` | POST | Bloquea usuario |
| `impersonateUser` | `/admin/impersonate-user` | POST | Inicia impersonación |
| `stopImpersonating` | `/admin/stop-impersonating` | POST | Termina impersonación |
| `revokeUserSession` | `/admin/revoke-user-session` | POST | Revoca sesión específica |
| `revokeUserSessions` | `/admin/revoke-user-sessions` | POST | Revoca todas las sesiones de usuario |
| `removeUser` | `/admin/remove-user` | POST | Elimina usuario |
| `setUserPassword` | `/admin/set-user-password` | POST | Establece password de usuario |
| `userHasPermission` | `/admin/has-permission` | POST | Verifica permisos de usuario |

### 3.2 Organization Plugin (`organization`)

Archivo: `packages/better-auth/src/plugins/organization/organization.ts`

#### Organización
| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `createOrganization` | `/organization/create` | POST |
| `updateOrganization` | `/organization/update` | POST |
| `deleteOrganization` | `/organization/delete` | POST |
| `setActiveOrganization` | `/organization/set-active` | POST |
| `getFullOrganization` | `/organization/get-full-organization` | GET |
| `listOrganizations` | `/organization/list` | GET |
| `checkOrganizationSlug` | `/organization/check-slug` | POST |

#### Miembros
| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `addMember` | `/organization/add-member` | POST |
| `removeMember` | `/organization/remove-member` | POST |
| `updateMemberRole` | `/organization/update-member-role` | POST |
| `leaveOrganization` | `/organization/leave` | POST |
| `listMembers` | `/organization/list-members` | GET |
| `getActiveMember` | `/organization/get-active-member` | GET |
| `getActiveMemberRole` | `/organization/get-active-member-role` | GET |

#### Invitaciones
| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `inviteMember` | `/organization/invite-member` | POST |
| `cancelInvitation` | `/organization/cancel-invitation` | POST |
| `acceptInvitation` | `/organization/accept-invitation` | POST |
| `rejectInvitation` | `/organization/reject-invitation` | POST |
| `getInvitation` | `/organization/get-invitation` | GET |
| `listInvitations` | `/organization/list-invitations` | GET |
| `listUserInvitations` | `/organization/list-user-invitations` | GET |

#### Teams (opcional, si `teams.enabled: true`)
| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `createTeam` | `/organization/create-team` | POST |
| `listOrganizationTeams` | `/organization/list-teams` | GET |
| `removeTeam` | `/organization/remove-team` | POST |
| `updateTeam` | `/organization/update-team` | POST |
| `setActiveTeam` | `/organization/set-active-team` | POST |
| `listUserTeams` | `/organization/list-user-teams` | GET |
| `listTeamMembers` | `/organization/list-team-members` | GET |
| `addTeamMember` | `/organization/add-team-member` | POST |
| `removeTeamMember` | `/organization/remove-team-member` | POST |

#### Permisos
| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `hasPermission` | `/organization/has-permission` | POST |
| `createRole` | `/organization/create-role` | POST |
| `updateRole` | `/organization/update-role` | POST |
| `deleteRole` | `/organization/delete-role` | POST |
| `getRole` | `/organization/get-role` | GET |
| `listRoles` | `/organization/list-roles` | GET |

### 3.3 Two-Factor Plugin (`two-factor`)

Comprende TOTP, OTP, y Backup Codes.

| Endpoint | Ruta HTTP | Método | Descripción |
|----------|-----------|--------|-------------|
| `enableTwoFactor` | `/two-factor/enable` | POST | Genera TOTP URI y backup codes |
| `disableTwoFactor` | `/two-factor/disable` | POST | Desactiva 2FA |
| `generateTOTP` | `/totp/generate` | POST | Genera un código TOTP desde un secreto |
| `getTOTPURI` | `/two-factor/get-totp-uri` | POST | Obtiene URI para QR |
| `verifyTOTP` | `/two-factor/verify-totp` | POST | Verifica código TOTP |
| `send2FaOTP` | `/two-factor/send-otp` | POST | Envía OTP (email/sms) |
| `verifyOTP` | `/two-factor/verify-otp` | POST | Verifica OTP |
| `verifyBackupCode` | `/two-factor/verify-backup-code` | POST | Verifica backup code |
| `generateBackupCodes` | `/two-factor/generate-backup-codes` | POST | Genera nuevos backup codes |

### 3.4 JWT Plugin (`jwt`)

| Endpoint | Ruta HTTP | Método | Descripción |
|----------|-----------|--------|-------------|
| `getJwks` | Configurable (default: `/jwks`) | GET | Retorna JSON Web Key Set |
| `getToken` | `/token` | GET | Genera JWT para sesión actual |
| `signJWT` | API server-side, no ruta pública cliente | POST | Firma JWT con payload arbitrario |
| `verifyJWT` | API server-side, no ruta pública cliente | POST | Verifica JWT |

### 3.5 Magic Link Plugin (`magic-link`)

| Endpoint | Ruta HTTP | Método | Descripción |
|----------|-----------|--------|-------------|
| `signInMagicLink` | `/sign-in/magic-link` | POST | Envía magic link por email |
| `magicLinkVerify` | `/magic-link/verify` | GET | Verifica token y autentica |

### 3.6 Email OTP Plugin (`email-otp`)

| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `sendVerificationOTP` | `/email-otp/send-verification-otp` | POST |
| `createVerificationOTP` | API server-side, no ruta pública cliente | POST |
| `getVerificationOTP` | `/email-otp/get-verification-otp` | GET |
| `checkVerificationOTP` | `/email-otp/check-verification-otp` | POST |
| `verifyEmailOTP` | `/email-otp/verify-email` | POST |
| `signInEmailOTP` | `/sign-in/email-otp` | POST |
| `requestPasswordResetEmailOTP` | `/email-otp/request-password-reset` | POST |
| `forgetPasswordEmailOTP` | `/forget-password/email-otp` | POST |
| `resetPasswordEmailOTP` | `/email-otp/reset-password` | POST |
| `requestEmailChangeEmailOTP` | `/email-otp/request-email-change` | POST |
| `changeEmailEmailOTP` | `/email-otp/change-email` | POST |

### 3.7 Phone Number Plugin (`phone-number`)

| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `signInPhoneNumber` | `/sign-in/phone-number` | POST |
| `sendPhoneNumberOTP` | `/phone-number/send-otp` | POST |
| `verifyPhoneNumber` | `/phone-number/verify` | POST |
| `requestPasswordResetPhoneNumber` | `/phone-number/request-password-reset` | POST |
| `resetPasswordPhoneNumber` | `/phone-number/reset-password` | POST |

### 3.8 Username Plugin (`username`)

| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `signInUsername` | `/sign-in/username` | POST |
| `isUsernameAvailable` | `/is-username-available` | GET |

### 3.9 Anonymous Plugin (`anonymous`)

| Endpoint | Ruta HTTP | Método |
|----------|-----------|--------|
| `signInAnonymous` | `/sign-in/anonymous` | POST |
| `deleteAnonymousUser` | `/delete-anonymous-user` | POST |
| `linkAccount` | Hook sobre rutas de linking/sign-in, no endpoint propio |

### 3.10 Otros Plugins

| Plugin | Endpoints principales |
|--------|----------------------|
| **bearer** | Middleware (no endpoints) |
| **multi-session** | `/multi-session/list-device-sessions`, `/multi-session/set-active`, `/multi-session/revoke` |
| **one-time-token** | `/one-time-token/generate`, `/one-time-token/verify` |
| **oauth-proxy** | `/oauth-proxy-callback` |
| **generic-oauth** | `/sign-in/oauth2`, `/oauth2/callback/:providerId`, `/oauth2/link` |
| **oidc-provider** | `/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/consent`, `/oauth2/token`, `/oauth2/userinfo`, `/oauth2/register`, `/oauth2/client/:id`, `/oauth2/endsession` |
| **mcp** | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/mcp/authorize`, `/mcp/token`, `/mcp/userinfo`, `/mcp/register`, `/mcp/get-session`, `/mcp/jwks` |
| **device-authorization** | `/device/code`, `/device/token`, `/device`, `/device/approve`, `/device/deny` |
| **open-api** | `/open-api/generate-schema`, configurable reference path (`/reference` default) |
| **siwe** | `/siwe/nonce`, `/siwe/verify` |
| **one-tap** | `/one-tap/callback` |
| **custom-session** | Sobrescribe `/get-session` |
| **access** | Helpers de control de acceso (no endpoints HTTP) |
| **additional-fields** | Extiende schema/rutas existentes (no endpoints propios) |
| **captcha** | Middleware (no endpoints) |
| **haveibeenpwned** | Middleware/password hash hook (no endpoints) |
| **last-login-method** | Actualiza DB en hooks (no endpoints) |

### 3.11 Packages/plugins externos oficiales

Estos plugins existen como packages upstream separados. En Ruby se mantienen como gems separadas cuando traen dependencias o superficie propia pesada; el core conserva shims de compatibilidad donde aplica.

| Upstream package | Ruby package/shim | Endpoints |
|------------------|-------------------|-----------|
| `@better-auth/passkey` | `better_auth-passkey` + shim core | `/passkey/generate-register-options`, `/passkey/verify-registration`, `/passkey/generate-authenticate-options`, `/passkey/verify-authentication`, `/passkey/list-user-passkeys`, `/passkey/update-passkey`, `/passkey/delete-passkey` |
| `@better-auth/api-key` | `better_auth-api-key` + shim core | `/api-key/create`, `/api-key/verify`, `/api-key/get`, `/api-key/update`, `/api-key/delete`, `/api-key/list`, `/api-key/delete-all-expired-api-keys` |
| `@better-auth/oauth-provider` | `better_auth-oauth-provider` + shim core | OAuth2/OIDC discovery, client, consent, token, introspection, revoke, userinfo, and logout endpoints |
| `@better-auth/sso` | `better_auth-sso` + shim core | `/sign-in/sso`, `/sso/register`, OIDC/SAML callbacks, provider CRUD, domain verification, SAML metadata/SLO |
| `@better-auth/scim` | `better_auth-scim` + shim core | SCIM provider management plus `/scim/v2/*` protocol endpoints |
| `@better-auth/stripe` | `better_auth-stripe` + shim core | `/subscription/*` and `/stripe/webhook` |
| `@better-auth/expo` | Ruby core plugin | `/expo-authorization-proxy`; kept in core because the server surface is small and has no required external dependency |
| `@dub/better-auth` | Ruby core plugin | `/dub/link` plus optional `/oauth2/callback/:providerId`; kept in core for now because it uses an injected Dub client and does not require the Dub gem |

---

## 4. Middlewares de Sesión

Archivo: `packages/better-auth/src/api/routes/session.ts`

| Middleware | Requisito | Uso |
|------------|-----------|-----|
| `sessionMiddleware` | Sesión válida | Operaciones generales |
| `sensitiveSessionMiddleware` | Sesión válida + NO cookie cache | Cambio de password, delete, etc. |
| `freshSessionMiddleware` | Sesión reciente (`freshAge`) | Operaciones críticas |
| `requestOnlySessionMiddleware` | Sesión si es client call | Endpoints híbridos |

---

## 5. Router HTTP

Archivo: `packages/better-auth/src/api/index.ts` (función `router`)

El router se crea con `createRouter` de `better-call` con:
- `basePath`: pathname de `baseURL` (default: `/api/auth`)
- `routerMiddleware`:
  - `originCheckMiddleware` en `/**`
  - Middlewares de plugins
- `onRequest`: Maneja disabled paths, plugins `onRequest`, rate limiting
- `onResponse`: Plugins `onResponse`, rate limiting
- `onError`: Logging y manejo de errores
- `skipTrailingSlashes`: Configurable (`advanced.skipTrailingSlashes`)

### Paths HTTP Base (ejemplos con basePath `/api/auth`):

```
GET    /api/auth/ok
GET    /api/auth/error
GET    /api/auth/get-session
POST   /api/auth/sign-in/social
POST   /api/auth/sign-in/email
POST   /api/auth/sign-up/email
POST   /api/auth/sign-out
POST   /api/auth/verify-email
POST   /api/auth/send-verification-email
POST   /api/auth/change-email
POST   /api/auth/change-password
POST   /api/auth/set-password
POST   /api/auth/update-user
POST   /api/auth/update-session
POST   /api/auth/reset-password
GET    /api/auth/reset-password/:token
POST   /api/auth/request-password-reset
POST   /api/auth/verify-password
GET    /api/auth/list-accounts
POST   /api/auth/link-social
POST   /api/auth/unlink-account
POST   /api/auth/get-access-token
POST   /api/auth/refresh-token
GET    /api/auth/account-info
GET    /api/auth/list-sessions
POST   /api/auth/revoke-session
POST   /api/auth/revoke-sessions
POST   /api/auth/revoke-other-sessions
GET    /api/auth/callback/:id
POST   /api/auth/delete-user
GET    /api/auth/delete-user/callback
```

---

## 6. Tests y Comportamiento Esperado

### Patrones de Testing (observados en `*.test.ts`)

1. **getTestInstance()**: Utilidad central que crea instancia de auth con DB SQLite en memoria por defecto
2. **auth.api.[endpoint]()**: Llamadas directas server-side sin HTTP
3. **client.[endpoint]()**: Llamadas vía cliente HTTP (usando `customFetchImpl` en tests)
4. **Cookie handling**: Tests verifican `set-cookie` headers, signed cookies, chunked cookies
5. **Session lifecycle**: Tests cubren creación, refresh, expiry, revocación
6. **Hooks**: Tests de before/after hooks globales y por plugin

### Comportamientos Clave Documentados en Tests

#### Session
- `getSession` retorna `null` cuando no hay cookie válida
- `freshSessionMiddleware` rechaza con 403 si sesión es más vieja que `freshAge`
- Session se actualiza en DB solo cuando `updateAge` ha pasado (throttling)
- `deferSessionRefresh`: GET retorna sesión sin writes, POST permite refresh
- Cookie cache (`session_data`) permite lectura sin DB hit

#### Sign Up
- Soporta campos adicionales definidos en `user.additionalFields`
- Valida longitud mínima/máxima de password
- Si `requireEmailVerification`: no crea sesión, retorna `token: null`
- Rollback transaccional si falla creación de sesión
- Captura `ipAddress` y `userAgent` de headers

#### Password Reset
- `requestPasswordReset` envía email con token
- `resetPassword` valida token y actualiza password
- `revokeSessionsOnPasswordReset` elimina todas las sesiones
- Rechaza `redirectTo` no trusted con 403

#### Hooks
- Before hooks pueden interceptar retornando JSON directamente
- Before hooks pueden modificar contexto (`return { context: {...} }`)
- After hooks pueden modificar respuesta y setear cookies adicionales
- Hooks de plugins se ejecutan después de hooks globales
- Chained hooks: un hook after puede lanzar error que es capturado por siguiente hook after

#### Dynamic BaseURL
- `baseURL: { allowedHosts: [...] }` resuelve por request usando `x-forwarded-host`
- Soporta wildcards (`*.vercel.app`)
- `fallback` se usa para hosts no permitidos
- Cada request obtiene su propio contexto aislado

---

## 7. Estructura de Tipos

### Auth Type

```typescript
type Auth<Options extends BetterAuthOptions> = {
  handler: (request: Request) => Promise<Response>;
  api: InferAPI<ReturnType<typeof router<Options>>["endpoints"]>;
  options: Options;
  $ERROR_CODES: InferPluginErrorCodes<Options> & typeof BASE_ERROR_CODES;
  $context: Promise<AuthContext<Options> & InferPluginContext<Options>>;
  $Infer: { Session: { session, user } } & InferPluginTypes<Options>;
};
```

### InferAPI
- Filtra endpoints con `metadata.scope: "http"` o `metadata.isAction: false` (no expuestos a `api` directo)
- `getSession` tiene tipo especial que soporta `asResponse`, `returnHeaders`, `query` con `disableCookieCache`/`disableRefresh`

---

## 8. Mecanismos Internos Importantes

### `toAuthEndpoints`
- Envuelve cada endpoint para soportar llamadas directas (`auth.api.*`)
- Resuelve `baseURL` dinámico por request
- Ejecuta before hooks -> handler -> after hooks
- Maneja `asResponse` (retorna Response), `returnHeaders`, `returnStatus`
- Re-lanza `APIError` en path no-response

### Contexto de Endpoint
Cada endpoint recibe `ctx` con:
- `ctx.context`: `AuthContext` (adapter, secret, options, logger, etc.)
- `ctx.body`: Body parseado
- `ctx.query`: Query params
- `ctx.headers`: Headers
- `ctx.request`: Request original (si existe)
- `ctx.session`: Sesión actual (si middleware la inyectó)
- Helpers: `ctx.json()`, `ctx.redirect()`, `ctx.setCookie()`, `ctx.setHeader()`, `ctx.error()`

### Plugins
Un plugin (`BetterAuthPlugin`) puede definir:
- `endpoints`: Endpoints adicionales
- `middlewares`: Middlewares de router
- `hooks.before/after`: Hooks globales
- `schema`: Schema de DB adicional
- `init()`: Modifica options en init time
- `onRequest/onResponse`: Interceptores de request/response
- `$ERROR_CODES`: Códigos de error custom
- `rateLimit`: Reglas de rate limiting

---

## 9. Archivos Clave del Upstream

| Archivo | Propósito |
|---------|-----------|
| `packages/better-auth/src/auth/base.ts` | Fábrica `createBetterAuth` |
| `packages/better-auth/src/auth/full.ts` | Entry point `betterAuth` (full mode) |
| `packages/better-auth/src/api/index.ts` | `getEndpoints`, `router` |
| `packages/better-auth/src/api/to-auth-endpoints.ts` | Wrapper para llamadas directas `auth.api.*` |
| `packages/better-auth/src/api/routes/*.ts` | Endpoints base (session, sign-in, password, etc.) |
| `packages/better-auth/src/types/auth.ts` | Tipos `Auth`, `InferAPI` |
| `packages/core/src/api/index.ts` | `createAuthEndpoint`, `createAuthMiddleware` |
| `packages/better-auth/src/plugins/*/index.ts` | Plugins y sus endpoints |
