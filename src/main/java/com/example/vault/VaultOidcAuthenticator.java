package com.example.vault;

import org.json.JSONObject;

import java.awt.Desktop;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Map;

public class VaultOidcAuthenticator {

    private final HttpClient http;

    private String  cachedToken;
    private Instant tokenExpiresAt;

    public VaultOidcAuthenticator() {
        this.http = HttpClient.newHttpClient();
    }

    // Package-private constructor for testing — allows injecting a mock HttpClient
    VaultOidcAuthenticator(HttpClient http) {
        this.http = http;
    }

    public String getToken() throws Exception {
        if (isTokenValid()) {
            System.out.println("[Auth] Using cached Vault token (expires: " + tokenExpiresAt + ")");
            return cachedToken;
        }
        return login();
    }

    // Package-private for testing — allows injecting a pre-fetched token
    void setCachedToken(String token, int ttlSeconds) {
        this.cachedToken    = token;
        this.tokenExpiresAt = Instant.now().plusSeconds(ttlSeconds - 60);
    }

    String fetchAuthUrl() throws Exception {
        String endpoint = VaultConfig.VAULT_ADDR + "/v1/auth/oidc/oidc/auth_url";

        String requestBody = new JSONObject()
            .put("role",         VaultConfig.VAULT_ROLE)
            .put("redirect_uri", VaultConfig.REDIRECT_URI)
            .toString();

        HttpResponse<String> response = http.send(
            HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );

        assertSuccess(response, "fetch OIDC auth URL");

        return new JSONObject(response.body())
            .getJSONObject("data")
            .getString("auth_url");
    }

    String exchangeCodeForToken(Map<String, String> callbackParams) throws Exception {
        String code  = callbackParams.get("code");
        String state = callbackParams.get("state");

        if (code == null || state == null) {
            throw new IllegalStateException(
                "OIDC callback missing 'code' or 'state'. Received: " + callbackParams
            );
        }

        String callbackUrl = String.format(
            "%s/v1/auth/oidc/oidc/callback?code=%s&state=%s",
            VaultConfig.VAULT_ADDR, code, state
        );

        HttpResponse<String> response = http.send(
            HttpRequest.newBuilder()
                .uri(URI.create(callbackUrl))
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );

        assertSuccess(response, "exchange OIDC code for Vault token");

        JSONObject auth      = new JSONObject(response.body()).getJSONObject("auth");
        int        leaseSecs = auth.getInt("lease_duration");
        String     token     = auth.getString("client_token");

        this.tokenExpiresAt = Instant.now().plusSeconds(leaseSecs - 60);
        this.cachedToken    = token;

        System.out.println("[Auth] Token obtained. TTL=" + leaseSecs + "s"
            + " | Policies=" + auth.getJSONArray("token_policies"));

        return token;
    }

    private String login() throws Exception {
        System.out.println("[Auth] Starting Vault OIDC login...");
        String authUrl = fetchAuthUrl();

        if (!Desktop.isDesktopSupported()) {
            throw new IllegalStateException(
                "No display available. Open this URL manually:\n" + authUrl
            );
        }

        System.out.println("[Auth] Opening browser — Windows SSO will complete automatically...");
        Desktop.getDesktop().browse(new URI(authUrl));

        Map<String, String> callbackParams = OidcCallbackServer.waitForCallback();
        return exchangeCodeForToken(callbackParams);
    }

    boolean isTokenValid() {
        return cachedToken != null
            && tokenExpiresAt != null
            && Instant.now().isBefore(tokenExpiresAt);
    }

    private void assertSuccess(HttpResponse<String> r, String op) {
        int status = r.statusCode();
        if (status < 200 || status >= 300) {
            throw new RuntimeException(
                "[Auth] Vault error during '" + op + "': HTTP " + status + "\n" + r.body()
            );
        }
    }
}
