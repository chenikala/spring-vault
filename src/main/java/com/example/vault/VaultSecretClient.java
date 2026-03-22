package com.example.vault;

import org.json.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

public class VaultSecretClient {

    private final HttpClient             http;
    private final VaultOidcAuthenticator authenticator;

    public VaultSecretClient() {
        this.http          = HttpClient.newHttpClient();
        this.authenticator = new VaultOidcAuthenticator();
    }

    // Package-private constructor for testing
    VaultSecretClient(HttpClient http, VaultOidcAuthenticator authenticator) {
        this.http          = http;
        this.authenticator = authenticator;
    }

    public Map<String, String> getAllSecrets() throws Exception {
        return getAllSecrets(VaultConfig.KV_MOUNT, VaultConfig.SECRET_PATH);
    }

    public Map<String, String> getAllSecrets(String kvMount, String secretPath) throws Exception {
        String vaultToken = authenticator.getToken();

        // KV v2 API path: /v1/{mount}/data/{path}
        String apiUrl = String.format(
            "%s/v1/%s/data/%s",
            VaultConfig.VAULT_ADDR,
            kvMount.replaceAll("^/|/$", ""),
            secretPath.replaceAll("^/", "")
        );

        System.out.println("[Vault] GET " + apiUrl);

        HttpResponse<String> response = http.send(
            HttpRequest.newBuilder()
                .uri(URI.create(apiUrl))
                .header("X-Vault-Token", vaultToken)
                .GET()
                .build(),
            HttpResponse.BodyHandlers.ofString()
        );

        assertSuccess(response, apiUrl);
        return parseKvV2Response(response.body());
    }

    /**
     * KV v2 response:
     * {
     *   "data": {
     *     "data":     { "key1": "val1", ... },   <- actual secrets
     *     "metadata": { "version": 1, ... }
     *   }
     * }
     */
    Map<String, String> parseKvV2Response(String responseBody) {
        JSONObject secretData = new JSONObject(responseBody)
            .getJSONObject("data")
            .getJSONObject("data");

        Map<String, String> secrets = new HashMap<>();
        for (String key : secretData.keySet()) {
            Object value = secretData.get(key);
            secrets.put(key, value != null ? value.toString() : null);
        }
        return secrets;
    }

    private void assertSuccess(HttpResponse<String> r, String url) {
        switch (r.statusCode()) {
            case 403 -> throw new RuntimeException(
                "[Vault] Access denied (403). Check your Vault policy for: " + url);
            case 404 -> throw new RuntimeException(
                "[Vault] Path not found (404). Check KV_MOUNT and SECRET_PATH: " + url);
            default -> {
                if (r.statusCode() < 200 || r.statusCode() >= 300)
                    throw new RuntimeException(
                        "[Vault] HTTP " + r.statusCode() + " for " + url + "\n" + r.body());
            }
        }
    }
}
