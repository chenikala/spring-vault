package com.example.vault;

public class VaultConfig {

    public static final String VAULT_ADDR    = "https://vault.company.com";
    public static final String VAULT_ROLE    = "your-oidc-role-name";
    public static final String SECRET_PATH   = "myapp/config";
    public static final String KV_MOUNT      = "secret";

    public static final int    CALLBACK_PORT = 8250;
    public static final String CALLBACK_PATH = "/oidc/callback";
    public static final String REDIRECT_URI  =
        "http://localhost:" + CALLBACK_PORT + CALLBACK_PATH;

    private VaultConfig() {}
}
