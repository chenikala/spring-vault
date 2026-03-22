# vault-oidc-client

A lightweight, plain Java client that authenticates to **HashiCorp Vault** using your **corporate Windows SSO credentials** via the OpenID Connect (OIDC) protocol — with zero username/password prompts.

---

## Table of Contents

- [Business Context](#business-context)
- [How It Works](#how-it-works)
- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Class Responsibilities](#class-responsibilities)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Running the Tests](#running-the-tests)
- [Understanding the OIDC Flow](#understanding-the-oidc-flow)
- [Token Caching and Expiry](#token-caching-and-expiry)
- [Security Design Decisions](#security-design-decisions)
- [Error Reference](#error-reference)
- [Extending the Project](#extending-the-project)
- [Glossary](#glossary)

---

## Business Context

Most enterprises store sensitive configuration values — database passwords, API keys, certificates, connection strings — inside **HashiCorp Vault**. Access to Vault is controlled by policies tied to identity.

The challenge for developers is: **how does a Java application prove its identity to Vault without embedding credentials in code or config files?**

This project solves that by delegating identity to the **corporate Identity Provider (IdP)** — the same system that handles your Windows login (Azure AD, Okta, ADFS, etc.). Because you are already logged in to Windows, your identity is proven automatically. No hardcoded secrets. No service accounts. No password prompts.

**The business value:**

- Developers get secrets securely without knowing Vault internals
- Security team controls access centrally via Active Directory groups
- Audit logs in Vault show exactly who accessed what and when
- Rotating secrets in Vault takes effect immediately without redeploying apps

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HIGH-LEVEL FLOW                             │
│                                                                     │
│  Your App          Browser            Corporate IdP       Vault     │
│  ────────          ───────            ─────────────       ─────     │
│                                                                     │
│  1. Start ──────────────────────────────────────────────────────>  │
│     Ask Vault for login URL                                         │
│  <── Login URL returned ────────────────────────────────────────── │
│                                                                     │
│  2. Open browser ──────────>                                        │
│                             Detect Windows session (SSO)            │
│                             Auto-authenticate (no password)         │
│                             <── Redirect with auth code ──────      │
│                                                                     │
│  3. Receive auth code <─────                                        │
│     Send code to Vault ─────────────────────────────────────────>  │
│                             Vault validates with IdP JWKS           │
│  <── Vault token returned ──────────────────────────────────────── │
│                                                                     │
│  4. Use Vault token to read secrets ────────────────────────────>  │
│  <── Secrets returned ──────────────────────────────────────────── │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

The key insight: **your Java app never sees your Windows password**. Identity flows from the OS session → browser → IdP → Vault. Your app only ever handles a short-lived Vault token.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     vault-oidc-client                   │
│                                                         │
│  ┌─────────────┐     ┌──────────────────────────────┐  │
│  │  VaultApp   │────>│      VaultSecretClient        │  │
│  │ (entry pt)  │     │  - getAllSecrets(path)        │  │
│  └─────────────┘     │  - parseKvV2Response()        │  │
│                      └──────────────┬───────────────┘  │
│                                     │ uses              │
│                      ┌──────────────▼───────────────┐  │
│                      │    VaultOidcAuthenticator     │  │
│                      │  - getToken()                 │  │
│                      │  - fetchAuthUrl()             │  │
│                      │  - exchangeCodeForToken()     │  │
│                      │  - isTokenValid() [cache]     │  │
│                      └──────────────┬───────────────┘  │
│                                     │ uses              │
│                      ┌──────────────▼───────────────┐  │
│                      │     OidcCallbackServer        │  │
│                      │  - waitForCallback()          │  │
│                      │  - parseQuery()               │  │
│                      └──────────────────────────────┘  │
│                                                         │
│  ┌─────────────┐                                        │
│  │ VaultConfig │  ← Central configuration constants     │
│  └─────────────┘                                        │
└─────────────────────────────────────────────────────────┘
```

The design follows the **Single Responsibility Principle** — each class does exactly one thing:

| Layer | Class | Responsibility |
|---|---|---|
| Entry Point | `VaultApp` | Start the app, print secrets |
| Secret Access | `VaultSecretClient` | Read secrets from Vault KV v2 |
| Authentication | `VaultOidcAuthenticator` | Obtain and cache Vault tokens |
| Callback | `OidcCallbackServer` | Capture the browser redirect |
| Configuration | `VaultConfig` | Hold all settings in one place |

---

## Project Structure

```
vault-oidc-client/
│
├── pom.xml                                          # Maven build — dependencies & plugins
│
└── src/
    ├── main/
    │   └── java/com/example/vault/
    │       ├── VaultApp.java                        # ← START HERE — main entry point
    │       ├── VaultConfig.java                     # ← SET YOUR VALUES HERE
    │       ├── VaultSecretClient.java               # Reads secrets from Vault KV v2
    │       ├── VaultOidcAuthenticator.java          # OIDC login + token management
    │       └── OidcCallbackServer.java              # Local HTTP server for SSO redirect
    │
    └── test/
        └── java/com/example/vault/
            └── VaultClientTest.java                 # 19 tests with embedded mock Vault server
```

> **New developer tip:** Start reading code in this order:
> `VaultConfig` → `VaultApp` → `VaultSecretClient` → `VaultOidcAuthenticator` → `OidcCallbackServer`

---

## Class Responsibilities

### `VaultConfig.java` — Configuration

The single source of truth for all settings. **This is the only file you need to edit** to connect to your environment.

```java
VAULT_ADDR    // Full URL of your Vault server
VAULT_ROLE    // OIDC role name configured by your Vault team
SECRET_PATH   // Path to the secrets you want to read (within the KV mount)
KV_MOUNT      // KV secrets engine mount name (usually "secret")
CALLBACK_PORT // Local port for OIDC redirect — must match Vault's allowed redirect URIs
```

---

### `VaultApp.java` — Entry Point

The `main()` method. Wires everything together and prints secrets to the console. In a real application, you would replace the `System.out.println` section with code that injects secrets into your app's configuration (e.g., setting a `DataSource` password, initializing an API client).

Sensitive values (passwords, keys, tokens) are **masked in console output** automatically via the `mask()` method. The original values are still available in the `Map` returned by `getAllSecrets()`.

---

### `VaultSecretClient.java` — Secret Reader

Handles all HTTP communication with the Vault KV v2 secrets engine.

**Why KV v2?** KV v2 (Key-Value version 2) adds versioning and metadata to secrets. The API path is slightly different from KV v1 — secrets are nested under a `data.data` JSON structure, which this class handles transparently.

```
KV v1 API:  GET /v1/secret/myapp/config
KV v2 API:  GET /v1/secret/data/myapp/config    ← note the extra /data/
Response:   { "data": { "data": { ...secrets... }, "metadata": {...} } }
```

This class also validates HTTP responses and throws clear, actionable errors for 403 and 404 — the two most common mistakes when first connecting.

---

### `VaultOidcAuthenticator.java` — Authentication Manager

Handles the three-step OIDC login:

1. Requests an auth URL from Vault (`/v1/auth/oidc/oidc/auth_url`)
2. Opens the browser (Windows SSO silently completes the login)
3. Exchanges the returned auth code for a Vault client token (`/v1/auth/oidc/oidc/callback`)

**Token caching:** Once a token is obtained, it is cached in memory with a 60-second safety buffer before its actual TTL expires. Subsequent calls to `getToken()` return the cached token immediately without any HTTP calls or browser interaction. The token is refreshed automatically when it approaches expiry.

---

### `OidcCallbackServer.java` — OIDC Redirect Listener

A minimal embedded HTTP server that runs only during the login sequence. It listens on `localhost:8250` for the browser redirect from the Identity Provider, parses the `code` and `state` parameters from the URL, and shuts itself down immediately afterward.

This is a standard pattern for **desktop/CLI OIDC flows** — the same approach used by the official `vault` CLI, the `gcloud` CLI, and many other developer tools. It is not a persistent web server; it starts and stops within the login sequence.

---

## Prerequisites

| Requirement | Version | Check Command |
|---|---|---|
| JDK | 17 or higher | `java -version` |
| Maven | 3.8 or higher | `mvn -version` |
| Windows | Domain-joined machine | — |
| Network | Access to Vault server and corporate IdP | — |

**Information to obtain from your Vault / IT team before starting:**

```
□ Vault server URL          e.g. https://vault.company.com
□ OIDC role name            e.g. "developer-role" or "app-read-role"
□ KV mount name             usually "secret" — confirm with Vault team
□ Secret path               e.g. "myapp/config" or "team/myapp/prod"
□ Redirect URI whitelisted  http://localhost:8250/oidc/callback (ask them to add this)
```

---

## Quick Start

```bash
# 1. Clone or unzip the project
cd vault-oidc-client

# 2. Edit VaultConfig.java with your real values (see Configuration section below)

# 3. Run tests — no real Vault needed, uses an embedded mock server
mvn test

# 4. Build the jar
mvn package -DskipTests

# 5. Run — browser will open, Windows SSO completes automatically
java -jar target/vault-oidc-client-1.0.0.jar
```

---

## Configuration

Open `src/main/java/com/example/vault/VaultConfig.java` and update the following constants:

```java
public class VaultConfig {

    // ✏️ Your Vault server address
    public static final String VAULT_ADDR  = "https://vault.company.com";

    // ✏️ OIDC role name — ask your Vault / platform team
    public static final String VAULT_ROLE  = "your-oidc-role-name";

    // ✏️ Path to your secrets within the KV mount
    //    e.g. if full Vault path is "secret/myapp/config", set this to "myapp/config"
    public static final String SECRET_PATH = "myapp/config";

    // ✏️ KV secrets engine mount — usually "secret", confirm with Vault team
    public static final String KV_MOUNT    = "secret";

    // Callback settings — only change port if 8250 is blocked on your machine
    public static final int    CALLBACK_PORT = 8250;
    public static final String CALLBACK_PATH = "/oidc/callback";
}
```

> **Important:** The redirect URI `http://localhost:8250/oidc/callback` must be registered as an allowed redirect URI in your corporate IdP app registration. Ask your Vault or Identity team to confirm this is already configured, or to add it.

---

## Running the Application

```bash
java -jar target/vault-oidc-client-1.0.0.jar
```

**Expected console output:**

```
====================================
  Vault OIDC Client (Plain Java)
====================================
Vault : https://vault.company.com
Path  : secret/data/myapp/config

[Auth] Starting Vault OIDC login...
[Auth] Opening browser — Windows SSO will complete automatically...
  Listening on port 8250...

  [Browser opens — Windows SSO detects your domain session and logs in silently]

[Auth] Token obtained. TTL=3600s | Policies=["read-secrets-policy"]
[Vault] GET https://vault.company.com/v1/secret/data/myapp/config

======= Secrets (4 found) =======
  db_host                   = db.internal.company.com
  db_password               = Su****99
  api_key                   = sk****ey
  environment               = production
=================================
```

**Integrating secrets into your application:**

Once you have the `Map<String, String>` from `getAllSecrets()`, use the values directly in your application:

```java
VaultSecretClient client = new VaultSecretClient();
Map<String, String> secrets = client.getAllSecrets();

// Database connection
String dbUrl      = secrets.get("db_host");
String dbPassword = secrets.get("db_password");

// API client
String apiKey = secrets.get("api_key");
```

---

## Running the Tests

```bash
mvn test
```

The test suite runs **19 tests** using an embedded mock Vault HTTP server — no real Vault connection, no browser, no Windows SSO required. Tests cover every class and every error condition.

**Test coverage:**

| Test Group | Tests | What is covered |
|---|---|---|
| `OidcCallbackServer` | 4 | Query string parsing — valid, null, blank, multi-param |
| `VaultOidcAuthenticator` | 6 | Token exchange, missing code, missing state, caching, expiry, auth URL fetch |
| `VaultSecretClient` | 5 | Secret fetch success, 403, 404, 500, KV v2 response parsing |
| `VaultApp` | 4 | Masking passwords, API keys, non-sensitive values, null values |

**Expected output:**

```
[INFO] Tests run: 19, Failures: 0, Errors: 0, Skipped: 0
```

**How the mock server works:**

`VaultClientTest` starts a real `com.sun.net.httpserver.HttpServer` on port `18200` before any tests run. It registers six routes that simulate Vault API responses — successful secret reads, token exchanges, 403 access denied, 404 not found, and 500 server errors. Tests override the authenticator and client to point at this mock server instead of a real Vault instance. The server stops after all tests complete.

---

## Understanding the OIDC Flow

This is the most important concept to understand when debugging or extending the project.

**Step 1 — Request auth URL from Vault**

```
POST https://vault.company.com/v1/auth/oidc/oidc/auth_url
Body: { "role": "your-role", "redirect_uri": "http://localhost:8250/oidc/callback" }

Response: { "data": { "auth_url": "https://login.microsoftonline.com/...?state=xyz&nonce=abc" } }
```

The `state` and `nonce` in the auth URL are security parameters generated by Vault. They prevent replay attacks. Vault remembers them and validates them when the code comes back.

**Step 2 — Browser completes SSO**

The browser navigates to the IdP URL. Because the user is on a domain-joined Windows machine, the browser sends a Kerberos ticket or NTLM token to the IdP automatically. The IdP validates it and redirects the browser back to:

```
http://localhost:8250/oidc/callback?code=AUTH_CODE_XYZ&state=xyz
```

`OidcCallbackServer` is listening here and captures the `code` and `state`.

**Step 3 — Exchange code for Vault token**

```
GET https://vault.company.com/v1/auth/oidc/oidc/callback?code=AUTH_CODE_XYZ&state=xyz

Response: {
  "auth": {
    "client_token": "hvs.xxxxxxxx",
    "lease_duration": 3600,
    "token_policies": ["read-secrets-policy"]
  }
}
```

Vault validates the code with the IdP, checks that the user's AD groups match the role's policy, and returns a scoped Vault token.

**Step 4 — Read secrets with Vault token**

```
GET https://vault.company.com/v1/secret/data/myapp/config
Header: X-Vault-Token: hvs.xxxxxxxx

Response: {
  "data": {
    "data": { "db_password": "...", "api_key": "..." },
    "metadata": { "version": 3 }
  }
}
```

---

## Token Caching and Expiry

The Vault token returned after OIDC login has a TTL (time-to-live), typically 1 hour, set by your Vault team's role configuration.

`VaultOidcAuthenticator` caches the token in memory with a **60-second safety buffer**:

```
tokenExpiresAt = now + (ttlSeconds - 60)
```

This means if Vault says the token expires at 14:00:00, the client considers it expired at 13:59:00 and will re-authenticate before making the next secret request. This prevents edge cases where a token expires mid-request.

```
Timeline example (TTL = 3600s):

09:00:00  Token obtained, cached until 09:59:00
09:00:01  getAllSecrets() → uses cached token ✅
09:30:00  getAllSecrets() → uses cached token ✅
09:59:00  Token considered expired (60s before actual expiry)
09:59:01  getAllSecrets() → triggers new OIDC login 🔄
```

In a long-running application, the browser will re-open when the token needs refreshing. If this is undesirable, ask your Vault team to increase the token TTL or enable token renewal.

---

## Security Design Decisions

**Why no credentials in config files?**
Hardcoded credentials in `application.properties` or environment variables are a security risk — they can be accidentally committed to version control, exposed in logs, or leaked via environment variable injection. OIDC delegates identity to the corporate IdP, which already manages credential security.

**Why is the callback server on localhost?**
The OIDC spec allows `localhost` redirect URIs for native and desktop applications (RFC 8252). The auth code delivered to `localhost:8250` is useless to an attacker because it is single-use, short-lived (usually 60 seconds), and requires the matching `state` value which only Vault and the original browser tab possess.

**Why is the Vault token stored in memory and not on disk?**
Disk-cached tokens (like `~/.vault-token`) persist across application restarts and can be read by other processes. In-memory tokens are automatically destroyed when the JVM exits and are scoped to the lifetime of your application session.

**Why mask secrets in console output?**
Secrets printed to stdout end up in application logs, CI/CD pipeline logs, and terminal scrollback buffers. The `mask()` method in `VaultApp` shows enough of the value to confirm it was read correctly (first 2 and last 2 characters) without exposing the full value.

---

## Error Reference

| Error | Most Likely Cause | Fix |
|---|---|---|
| `HTTP 403 Access denied` | Your AD group is not mapped to a Vault policy, or the token doesn't have read access to the secret path | Ask your Vault team to grant your role access to `secret/data/your/path` |
| `HTTP 404 Path not found` | `SECRET_PATH` or `KV_MOUNT` in `VaultConfig` is wrong | Verify the exact path in the Vault UI or with `vault kv get secret/your/path` |
| `Connection refused` | `VAULT_ADDR` is wrong or Vault is unreachable from your network | Check VPN, firewall, and the URL with your Vault team |
| `No display available` | Application is running on a headless server (no GUI) | Run on a desktop machine, or ask your Vault team for an AppRole or pre-generated token |
| `Timeout waiting for callback` | Browser did not complete SSO within 2 minutes | Check if your browser is domain-joined; try opening the printed auth URL manually |
| `Missing 'code' or 'state'` | IdP redirected to callback without required params | Usually indicates the redirect URI is not whitelisted — confirm with your Identity team |
| `Port 8250 already in use` | Another process is using port 8250 | Change `CALLBACK_PORT` in `VaultConfig` and ask Vault team to whitelist the new redirect URI |

---

## Extending the Project

**Reading from multiple secret paths:**

```java
VaultSecretClient client = new VaultSecretClient();

Map<String, String> dbSecrets  = client.getAllSecrets("secret", "myapp/database");
Map<String, String> apiSecrets = client.getAllSecrets("secret", "myapp/external-apis");
Map<String, String> certSecrets = client.getAllSecrets("secret", "myapp/certificates");
```

**Using secrets to configure a database connection:**

```java
Map<String, String> secrets = client.getAllSecrets();

HikariConfig config = new HikariConfig();
config.setJdbcUrl("jdbc:postgresql://" + secrets.get("db_host") + "/mydb");
config.setUsername(secrets.get("db_username"));
config.setPassword(secrets.get("db_password"));
HikariDataSource dataSource = new HikariDataSource(config);
```

**Adding Vault namespace support (enterprise Vault):**
Some organisations use Vault namespaces to separate teams. Add this header to all HTTP requests:

```java
.header("X-Vault-Namespace", "your-namespace")
```

**Running on a headless server (non-interactive):**
If your application runs in a CI/CD pipeline or on a server without a browser, switch to Vault's **AppRole** auth method instead of OIDC. AppRole uses a `role_id` and `secret_id` that your platform team injects as environment variables. OIDC is designed for developer workstations and interactive use.

---

## Glossary

| Term | Plain English Explanation |
|---|---|
| **OIDC** | OpenID Connect — a login protocol built on OAuth 2.0. Lets your app say "I trust the corporate IdP to verify who this user is." |
| **IdP** | Identity Provider — the system that knows who you are. In most enterprises this is Azure AD, Okta, or ADFS — the same system behind your Windows login. |
| **OIDC auth URL** | A one-time URL generated by Vault that points to the IdP's login page, with security parameters embedded. |
| **Auth code** | A short-lived, single-use code the IdP gives the browser after login. Your app trades this code for a real token. |
| **Vault token** | A temporary credential (like a session cookie) that Vault gives your app after it proves who you are. All subsequent Vault API calls use this token. |
| **KV v2** | Key-Value secrets engine version 2 — Vault's standard way to store key/value pairs with versioning and metadata. |
| **TTL** | Time-to-live — how long a Vault token is valid before it expires. Typically set to 1 hour by your Vault team. |
| **SPNEGO / Kerberos** | The protocol Windows uses under the hood to prove your identity to the browser and IdP without re-entering your password. |
| **Role** | A named set of rules in Vault that controls which users can authenticate and what secrets they can access. Your Vault team creates the role and links it to AD groups. |
| **Policy** | A Vault document that defines which secret paths are readable or writable. Roles are assigned one or more policies. |
| **Redirect URI** | The URL the IdP sends the browser to after login. Must be pre-registered with the IdP to prevent attackers from redirecting auth codes to malicious servers. |
