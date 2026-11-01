package com.ecommerce.authuser.internal.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Verifies the {@code X-Internal-Service-Token} header used by internal
 * service-to-service endpoints under {@code /api/v1/internal/**}.
 *
 * <p>When no token is configured every call is rejected, so the endpoints
 * stay closed by default.</p>
 */
@Component
public class InternalServiceTokenVerifier {

    private final byte[] expectedToken;

    public InternalServiceTokenVerifier(
            @Value("${auth.internal.service-token:}") String expectedToken
    ) {
        this.expectedToken = expectedToken == null || expectedToken.isBlank()
                ? null
                : expectedToken.getBytes(StandardCharsets.UTF_8);
    }

    public void verify(String presentedToken) {
        if (expectedToken == null
                || presentedToken == null
                || presentedToken.isBlank()) {
            throw new InternalServiceTokenInvalidException();
        }

        byte[] presented = presentedToken.getBytes(StandardCharsets.UTF_8);

        if (!MessageDigest.isEqual(expectedToken, presented)) {
            throw new InternalServiceTokenInvalidException();
        }
    }
}
