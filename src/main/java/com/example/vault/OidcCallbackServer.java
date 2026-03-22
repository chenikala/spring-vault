package com.example.vault;

import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class OidcCallbackServer {

    private static final String SUCCESS_HTML = """
        <html>
        <body style="font-family:sans-serif; text-align:center; padding:60px;">
            <h2>&#10003; Login Successful</h2>
            <p>You can close this tab and return to your application.</p>
        </body>
        </html>
        """;

    public static Map<String, String> waitForCallback() throws Exception {
        CompletableFuture<Map<String, String>> future = new CompletableFuture<>();

        HttpServer server = HttpServer.create(
            new InetSocketAddress("localhost", VaultConfig.CALLBACK_PORT), 0
        );

        server.createContext(VaultConfig.CALLBACK_PATH, exchange -> {
            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getQuery());

                byte[] body = SUCCESS_HTML.getBytes();
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.getResponseBody().close();

                future.complete(params);
            } catch (Exception e) {
                future.completeExceptionally(e);
            } finally {
                exchange.close();
            }
        });

        server.start();
        System.out.println("  Listening on port " + VaultConfig.CALLBACK_PORT + "...");

        try {
            return future.get(120, TimeUnit.SECONDS);
        } finally {
            server.stop(0);
        }
    }

    static Map<String, String> parseQuery(String query) {
        if (query == null || query.isBlank()) return Map.of();
        return Arrays.stream(query.split("&"))
            .map(pair -> pair.split("=", 2))
            .filter(p -> p.length == 2)
            .collect(Collectors.toMap(p -> p[0], p -> p[1]));
    }
}
