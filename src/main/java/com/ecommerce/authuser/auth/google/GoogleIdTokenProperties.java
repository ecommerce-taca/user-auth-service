package com.ecommerce.authuser.auth.google;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "auth.google")
public record GoogleIdTokenProperties(
        List<String> allowedClientIds,
        String jwkSetUri,
        String authorizationClientId,
        String authorizationClientSecret,
        String authorizationRedirectUri,
        Boolean authorizationCookieSecure
) {
    public List<String> resolvedAllowedClientIds() {
        return allowedClientIds == null
                ? List.of()
                : allowedClientIds.stream()
                        .filter(clientId -> clientId != null && !clientId.isBlank())
                        .map(String::trim)
                        .distinct()
                        .toList();
    }

    public String resolvedJwkSetUri() {
        return jwkSetUri == null || jwkSetUri.isBlank()
                ? "https://www.googleapis.com/oauth2/v3/certs"
                : jwkSetUri.trim();
    }

    public boolean codeFlowConfigured() {
        return hasText(authorizationClientId)
                && hasText(authorizationClientSecret)
                && hasText(authorizationRedirectUri);
    }

    public String resolvedAuthorizationClientId() {
        return authorizationClientId.trim();
    }

    public String resolvedAuthorizationClientSecret() {
        return authorizationClientSecret.trim();
    }

    public String resolvedAuthorizationRedirectUri() {
        return authorizationRedirectUri.trim();
    }

    public boolean resolvedAuthorizationCookieSecure() {
        return !Boolean.FALSE.equals(authorizationCookieSecure);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
