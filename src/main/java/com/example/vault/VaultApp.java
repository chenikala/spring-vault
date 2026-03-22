package com.example.vault;

import java.util.Map;

public class VaultApp {

    public static void main(String[] args) throws Exception {

        System.out.println("====================================");
        System.out.println("  Vault OIDC Client (Plain Java)   ");
        System.out.println("====================================");
        System.out.println("Vault : " + VaultConfig.VAULT_ADDR);
        System.out.println("Path  : " + VaultConfig.KV_MOUNT + "/data/" + VaultConfig.SECRET_PATH);
        System.out.println();

        VaultSecretClient client = new VaultSecretClient();

        Map<String, String> secrets = client.getAllSecrets();

        System.out.println();
        System.out.println("======= Secrets (" + secrets.size() + " found) =======");
        secrets.forEach((key, value) ->
            System.out.printf("  %-25s = %s%n", key, mask(key, value))
        );
        System.out.println("=====================================");
    }

    static String mask(String key, String value) {
        boolean sensitive = key.toLowerCase().matches(".*(password|secret|token|key|cert).*");
        if (sensitive && value != null && value.length() > 4) {
            return value.substring(0, 2) + "****" + value.substring(value.length() - 2);
        }
        return value;
    }
}
