package com.ecommerce.authuser.internal.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InternalServiceTokenVerifierTest {

    @Test
    void verify_shouldAcceptMatchingToken() {
        InternalServiceTokenVerifier verifier = new InternalServiceTokenVerifier("secret-token");

        assertDoesNotThrow(() -> verifier.verify("secret-token"));
    }

    @Test
    void verify_shouldRejectWrongOrMissingToken() {
        InternalServiceTokenVerifier verifier = new InternalServiceTokenVerifier("secret-token");

        assertThrows(InternalServiceTokenInvalidException.class, () -> verifier.verify("other"));
        assertThrows(InternalServiceTokenInvalidException.class, () -> verifier.verify(null));
        assertThrows(InternalServiceTokenInvalidException.class, () -> verifier.verify(" "));
    }

    @Test
    void verify_shouldRejectEverythingWhenTokenNotConfigured() {
        InternalServiceTokenVerifier verifier = new InternalServiceTokenVerifier("");

        assertThrows(InternalServiceTokenInvalidException.class, () -> verifier.verify(""));
        assertThrows(InternalServiceTokenInvalidException.class, () -> verifier.verify("anything"));
    }
}
