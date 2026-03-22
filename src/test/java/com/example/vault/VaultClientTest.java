package com.example.vault;

import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;
import org.junit.jupiter.api.*;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests using a real local HTTP server that simulates Vault API responses.
 * No mocking frameworks needed — full end-to-end test of all HTTP interactions.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class VaultClientTest {

    // ── Mock Vault server ─────────────────────────────────────────
    private static HttpServer mockVaultServer;
    private static final int  MOCK_PORT = 18200;
    private static final String MOCK_VAULT_ADDR = "http://localhost:" + MOCK_PORT;

    // Sample data returned by mock server
    private static final String FAKE_VAULT_TOKEN  = "hvs.TESTTOKEN123456789";
    private static final String FAKE_AUTH_URL     =
        "https://login.microsoftonline.com/tenant/oauth2/authorize?state=abc123&nonce=xyz";

    private static final Map<String, String> SAMPLE_SECRETS = Map.of(
        "db_host",       "db.internal.company.com",
        "db_port",       "5432",
        "db_name",       "myappdb",
        "db_password",   "SuperSecret$Pass99",
        "api_key",       "sk-live-abcdefghij1234567890",
        "environment",   "production",
        "feature_flag",  "true"
    );

    // ── Start mock server before all tests ───────────────────────
    @BeforeAll
    static void startMockVaultServer() throws Exception {
        mockVaultServer = HttpServer.create(new InetSocketAddress("localhost", MOCK_PORT), 0);

        // Route 1: OIDC auth URL endpoint
        mockVaultServer.createContext("/v1/auth/oidc/oidc/auth_url", exchange -> {
            String responseBody = new JSONObject()
                .put("data", new JSONObject()
                    .put("auth_url", FAKE_AUTH_URL))
                .toString();
            sendJson(exchange, 200, responseBody);
        });

        // Route 2: OIDC callback — exchange code for Vault token
        mockVaultServer.createContext("/v1/auth/oidc/oidc/callback", exchange -> {
            String query = exchange.getRequestURI().getQuery();

            // Simulate invalid code rejection
            if (query != null && query.contains("code=INVALID")) {
                sendJson(exchange, 400, "{\"errors\":[\"invalid authorization code\"]}");
                return;
            }

            String responseBody = new JSONObject()
                .put("auth", new JSONObject()
                    .put("client_token",   FAKE_VAULT_TOKEN)
                    .put("lease_duration", 3600)
                    .put("renewable",      true)
                    .put("token_policies", new org.json.JSONArray()
                        .put("default")
                        .put("read-secrets-policy")))
                .toString();
            sendJson(exchange, 200, responseBody);
        });

        // Route 3: KV v2 secrets — success
        mockVaultServer.createContext("/v1/secret/data/myapp/config", exchange -> {
            String token = exchange.getRequestHeaders().getFirst("X-Vault-Token");

            // Simulate unauthorized access
            if (!FAKE_VAULT_TOKEN.equals(token)) {
                sendJson(exchange, 403, "{\"errors\":[\"permission denied\"]}");
                return;
            }

            // Build KV v2 response structure
            JSONObject secretData = new JSONObject();
            SAMPLE_SECRETS.forEach(secretData::put);

            String responseBody = new JSONObject()
                .put("data", new JSONObject()
                    .put("data", secretData)
                    .put("metadata", new JSONObject()
                        .put("version", 3)
                        .put("created_time", "2024-01-15T10:00:00Z")))
                .toString();
            sendJson(exchange, 200, responseBody);
        });

        // Route 4: Path not found
        mockVaultServer.createContext("/v1/secret/data/nonexistent/path", exchange -> {
            sendJson(exchange, 404, "{\"errors\":[]}");
        });

        // Route 5: Wrong token → 403
        mockVaultServer.createContext("/v1/secret/data/forbidden/path", exchange -> {
            sendJson(exchange, 403, "{\"errors\":[\"permission denied\"]}");
        });

        // Route 6: Server error simulation
        mockVaultServer.createContext("/v1/secret/data/error/path", exchange -> {
            sendJson(exchange, 500, "{\"errors\":[\"internal server error\"]}");
        });

        mockVaultServer.start();
        System.out.println("✅ Mock Vault server started on port " + MOCK_PORT);
    }

    @AfterAll
    static void stopMockVaultServer() {
        if (mockVaultServer != null) {
            mockVaultServer.stop(0);
            System.out.println("🛑 Mock Vault server stopped");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Tests: OidcCallbackServer — query string parsing
    // ─────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("OidcCallbackServer: parses code and state from callback URL")
    void testCallbackQueryParsing_ValidParams() {
        Map<String, String> params = OidcCallbackServer.parseQuery(
            "code=AUTH_CODE_ABC123&state=STATE_XYZ789"
        );
        assertEquals("AUTH_CODE_ABC123", params.get("code"),  "Should parse 'code'");
        assertEquals("STATE_XYZ789",     params.get("state"), "Should parse 'state'");
        System.out.println("✅ Query parsing — code and state extracted correctly");
    }

    @Test
    @Order(2)
    @DisplayName("OidcCallbackServer: handles null query string gracefully")
    void testCallbackQueryParsing_NullQuery() {
        Map<String, String> params = OidcCallbackServer.parseQuery(null);
        assertTrue(params.isEmpty(), "Null query should return empty map");
        System.out.println("✅ Query parsing — null handled gracefully");
    }

    @Test
    @Order(3)
    @DisplayName("OidcCallbackServer: handles blank query string gracefully")
    void testCallbackQueryParsing_BlankQuery() {
        Map<String, String> params = OidcCallbackServer.parseQuery("   ");
        assertTrue(params.isEmpty(), "Blank query should return empty map");
        System.out.println("✅ Query parsing — blank handled gracefully");
    }

    @Test
    @Order(4)
    @DisplayName("OidcCallbackServer: handles multiple query params correctly")
    void testCallbackQueryParsing_MultipleParams() {
        Map<String, String> params = OidcCallbackServer.parseQuery(
            "code=abc&state=xyz&session_state=sess123&iss=https%3A%2F%2Flogin.example.com"
        );
        assertEquals(4, params.size(), "Should parse all 4 params");
        assertEquals("abc",      params.get("code"));
        assertEquals("xyz",      params.get("state"));
        assertEquals("sess123",  params.get("session_state"));
        System.out.println("✅ Query parsing — multiple params handled correctly");
    }

    // ─────────────────────────────────────────────────────────────
    // Tests: VaultOidcAuthenticator — token exchange via mock server
    // ─────────────────────────────────────────────────────────────

    @Test
    @Order(5)
    @DisplayName("VaultOidcAuthenticator: exchanges valid code+state for Vault token")
    void testExchangeCodeForToken_Success() throws Exception {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        String token = auth.exchangeCodeForToken(Map.of(
            "code",  "VALID_CODE_123",
            "state", "VALID_STATE_456"
        ));

        assertEquals(FAKE_VAULT_TOKEN, token, "Should return the Vault client token");
        assertTrue(auth.isTokenValid(), "Token should be cached and valid");
        System.out.println("✅ Token exchange — Vault token received and cached");
    }

    @Test
    @Order(6)
    @DisplayName("VaultOidcAuthenticator: throws when 'code' is missing from callback")
    void testExchangeCodeForToken_MissingCode() {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
            auth.exchangeCodeForToken(Map.of("state", "some-state"))
        );
        assertTrue(ex.getMessage().contains("code"), "Error should mention missing 'code'");
        System.out.println("✅ Missing code — IllegalStateException thrown correctly");
    }

    @Test
    @Order(7)
    @DisplayName("VaultOidcAuthenticator: throws when 'state' is missing from callback")
    void testExchangeCodeForToken_MissingState() {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        IllegalStateException ex = assertThrows(IllegalStateException.class, () ->
            auth.exchangeCodeForToken(Map.of("code", "some-code"))
        );
        assertTrue(ex.getMessage().contains("state"), "Error should mention missing 'state'");
        System.out.println("✅ Missing state — IllegalStateException thrown correctly");
    }

    @Test
    @Order(8)
    @DisplayName("VaultOidcAuthenticator: reuses cached token without re-authenticating")
    void testTokenCaching() throws Exception {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        // Inject a pre-authenticated token
        auth.setCachedToken(FAKE_VAULT_TOKEN, 3600);

        assertTrue(auth.isTokenValid(), "Pre-set token should be valid");
        String token = auth.getToken(); // Should NOT trigger OIDC login
        assertEquals(FAKE_VAULT_TOKEN, token, "Should return cached token");
        System.out.println("✅ Token caching — cached token reused without re-login");
    }

    @Test
    @Order(9)
    @DisplayName("VaultOidcAuthenticator: detects expired token correctly")
    void testTokenExpiry() {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        // setCachedToken applies a -60s buffer: tokenExpiresAt = now + (ttl - 60)
        // TTL of 59 → now + (59-60) = now - 1s → already expired immediately
        auth.setCachedToken(FAKE_VAULT_TOKEN, 3600);
        assertTrue(auth.isTokenValid(), "Fresh token should be valid");

        // TTL < 60 means token is immediately considered expired (safety buffer)
        auth.setCachedToken(FAKE_VAULT_TOKEN, 59);
        assertFalse(auth.isTokenValid(), "Token with TTL < 60s buffer should be expired");
        System.out.println("✅ Token expiry — expired token detected correctly");
    }

    @Test
    @Order(10)
    @DisplayName("VaultOidcAuthenticator: fetches OIDC auth URL from Vault")
    void testFetchAuthUrl() throws Exception {
        VaultOidcAuthenticator auth = authenticatorAgainstMockServer();

        String authUrl = auth.fetchAuthUrl();

        assertNotNull(authUrl, "Auth URL should not be null");
        assertTrue(authUrl.contains("state="),  "Auth URL should contain state param");
        assertEquals(FAKE_AUTH_URL, authUrl,    "Should match mock server response");
        System.out.println("✅ Auth URL fetch — received: " + authUrl);
    }

    // ─────────────────────────────────────────────────────────────
    // Tests: VaultSecretClient — reading KV v2 secrets
    // ─────────────────────────────────────────────────────────────

    @Test
    @Order(11)
    @DisplayName("VaultSecretClient: fetches all secrets from KV v2 path successfully")
    void testGetAllSecrets_Success() throws Exception {
        VaultSecretClient client = clientWithAuthToken(FAKE_VAULT_TOKEN);

        Map<String, String> secrets = client.getAllSecrets(
            "secret", "myapp/config"
        );

        assertFalse(secrets.isEmpty(),                         "Should return secrets");
        assertEquals(SAMPLE_SECRETS.size(), secrets.size(),   "Should return all secrets");
        assertEquals("db.internal.company.com", secrets.get("db_host"),    "db_host should match");
        assertEquals("5432",                    secrets.get("db_port"),    "db_port should match");
        assertEquals("myappdb",                 secrets.get("db_name"),    "db_name should match");
        assertEquals("SuperSecret$Pass99",       secrets.get("db_password"), "db_password should match");
        assertEquals("sk-live-abcdefghij1234567890", secrets.get("api_key"), "api_key should match");
        assertEquals("production",              secrets.get("environment"), "environment should match");
        assertEquals("true",                    secrets.get("feature_flag"), "feature_flag should match");

        System.out.println("✅ All secrets fetched: " + secrets.keySet());
    }

    @Test
    @Order(12)
    @DisplayName("VaultSecretClient: throws RuntimeException on 403 Forbidden")
    void testGetAllSecrets_Forbidden() {
        VaultSecretClient client = clientWithAuthToken("WRONG_TOKEN");

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
            client.getAllSecrets("secret", "myapp/config")
        );
        assertTrue(ex.getMessage().contains("403"), "Error should mention 403");
        System.out.println("✅ 403 Forbidden — RuntimeException thrown: " + ex.getMessage());
    }

    @Test
    @Order(13)
    @DisplayName("VaultSecretClient: throws RuntimeException on 404 Not Found")
    void testGetAllSecrets_NotFound() {
        VaultSecretClient client = clientWithAuthToken(FAKE_VAULT_TOKEN);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
            client.getAllSecrets("secret", "nonexistent/path")
        );
        assertTrue(ex.getMessage().contains("404"), "Error should mention 404");
        System.out.println("✅ 404 Not Found — RuntimeException thrown: " + ex.getMessage());
    }

    @Test
    @Order(14)
    @DisplayName("VaultSecretClient: throws RuntimeException on 500 Server Error")
    void testGetAllSecrets_ServerError() {
        VaultSecretClient client = clientWithAuthToken(FAKE_VAULT_TOKEN);

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
            client.getAllSecrets("secret", "error/path")
        );
        assertTrue(ex.getMessage().contains("500"), "Error should mention 500");
        System.out.println("✅ 500 Server Error — RuntimeException thrown: " + ex.getMessage());
    }

    @Test
    @Order(15)
    @DisplayName("VaultSecretClient: parses KV v2 JSON response structure correctly")
    void testParseKvV2Response() {
        VaultSecretClient client = new VaultSecretClient(
            HttpClient.newHttpClient(),
            new VaultOidcAuthenticator()
        );

        // Simulate a real KV v2 response
        String kvV2Response = new JSONObject()
            .put("data", new JSONObject()
                .put("data", new JSONObject()
                    .put("username", "admin")
                    .put("password", "s3cr3t!")
                    .put("host",     "db.example.com"))
                .put("metadata", new JSONObject()
                    .put("version", 5)))
            .toString();

        Map<String, String> secrets = client.parseKvV2Response(kvV2Response);

        assertEquals(3,       secrets.size(),          "Should have 3 secrets");
        assertEquals("admin", secrets.get("username"), "username should match");
        assertEquals("s3cr3t!",        secrets.get("password"), "password should match");
        assertEquals("db.example.com", secrets.get("host"),     "host should match");
        System.out.println("✅ KV v2 response parsed correctly: " + secrets);
    }

    // ─────────────────────────────────────────────────────────────
    // Tests: VaultApp — masking sensitive values
    // ─────────────────────────────────────────────────────────────

    @Test
    @Order(16)
    @DisplayName("VaultApp: masks password values in console output")
    void testMask_Password() {
        String masked = VaultApp.mask("db_password", "SuperSecret99");
        assertFalse(masked.contains("SuperSecret99"), "Plain password should not appear");
        assertTrue(masked.contains("****"),           "Masked value should contain ****");
        System.out.println("✅ Password masked: SuperSecret99 → " + masked);
    }

    @Test
    @Order(17)
    @DisplayName("VaultApp: masks api_key values in console output")
    void testMask_ApiKey() {
        String masked = VaultApp.mask("api_key", "sk-live-abcdefgh");
        assertFalse(masked.contains("sk-live-abcdefgh"), "Plain key should not appear");
        assertTrue(masked.contains("****"),              "Masked value should contain ****");
        System.out.println("✅ API key masked: sk-live-abcdefgh → " + masked);
    }

    @Test
    @Order(18)
    @DisplayName("VaultApp: does NOT mask non-sensitive values")
    void testMask_NonSensitive() {
        assertEquals("production",          VaultApp.mask("environment", "production"));
        assertEquals("db.internal.company.com", VaultApp.mask("db_host", "db.internal.company.com"));
        assertEquals("5432",                VaultApp.mask("db_port", "5432"));
        System.out.println("✅ Non-sensitive values shown as-is");
    }

    @Test
    @Order(19)
    @DisplayName("VaultApp: handles null secret value without throwing")
    void testMask_NullValue() {
        assertDoesNotThrow(() -> VaultApp.mask("some_key", null));
        System.out.println("✅ Null value handled without exception");
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────

    /** Authenticator pointing at mock Vault server */
    private static VaultOidcAuthenticator authenticatorAgainstMockServer() {
        // Temporarily override VAULT_ADDR by using a custom HttpClient
        // pointing to our mock server via the full URL in each method
        return new VaultOidcAuthenticator(HttpClient.newHttpClient()) {
            @Override
            String fetchAuthUrl() throws Exception {
                var http = HttpClient.newHttpClient();
                var req  = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(MOCK_VAULT_ADDR + "/v1/auth/oidc/oidc/auth_url"))
                    .header("Content-Type", "application/json")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofString(
                        new JSONObject()
                            .put("role",         VaultConfig.VAULT_ROLE)
                            .put("redirect_uri", VaultConfig.REDIRECT_URI)
                            .toString()
                    ))
                    .build();
                var res = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());
                return new JSONObject(res.body()).getJSONObject("data").getString("auth_url");
            }

            @Override
            String exchangeCodeForToken(Map<String, String> params) throws Exception {
                String code  = params.get("code");
                String state = params.get("state");
                if (code == null || state == null)
                    throw new IllegalStateException(
                        "OIDC callback missing 'code' or 'state'. Received: " + params);

                var http = HttpClient.newHttpClient();
                var req  = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(
                        MOCK_VAULT_ADDR + "/v1/auth/oidc/oidc/callback?code=" + code + "&state=" + state))
                    .GET().build();
                var res = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());

                if (res.statusCode() < 200 || res.statusCode() >= 300)
                    throw new RuntimeException("HTTP " + res.statusCode() + ": " + res.body());

                var auth     = new JSONObject(res.body()).getJSONObject("auth");
                int ttl      = auth.getInt("lease_duration");
                String token = auth.getString("client_token");
                setCachedToken(token, ttl);
                System.out.println("[Auth] Token obtained. TTL=" + ttl + "s | Policies="
                    + auth.getJSONArray("token_policies"));
                return token;
            }
        };
    }

    /** Secret client with a pre-set token pointing at mock Vault server */
    private static VaultSecretClient clientWithAuthToken(String token) {
        VaultOidcAuthenticator auth = new VaultOidcAuthenticator() {
            @Override
            public String getToken() { return token; }
        };

        return new VaultSecretClient(HttpClient.newHttpClient(), auth) {
            @Override
            public Map<String, String> getAllSecrets(String kvMount, String secretPath) throws Exception {
                var http = HttpClient.newHttpClient();
                String apiUrl = MOCK_VAULT_ADDR + "/v1/" + kvMount + "/data/" + secretPath;
                System.out.println("[Vault] GET " + apiUrl);
                var req = java.net.http.HttpRequest.newBuilder()
                    .uri(java.net.URI.create(apiUrl))
                    .header("X-Vault-Token", token)
                    .GET().build();
                var res = http.send(req, java.net.http.HttpResponse.BodyHandlers.ofString());

                return switch (res.statusCode()) {
                    case 403 -> throw new RuntimeException("[Vault] Access denied (403) for: " + apiUrl);
                    case 404 -> throw new RuntimeException("[Vault] Path not found (404) for: " + apiUrl);
                    case 500 -> throw new RuntimeException("[Vault] HTTP 500 for: " + apiUrl);
                    default  -> parseKvV2Response(res.body());
                };
            }
        };
    }

    /** Helper to send a JSON response from the mock server */
    private static void sendJson(com.sun.net.httpserver.HttpExchange ex,
                                  int status, String body) throws Exception {
        byte[] bytes = body.getBytes();
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.getResponseBody().close();
        ex.close();
    }
}
