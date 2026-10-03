package com.ecommerce.authuser.auth.application.password;

import com.ecommerce.authuser.auth.application.session.SessionTokenPair;

public record PasswordChangeResult(
        boolean allSessions,
        long revokedSessionCount,
        SessionTokenPair sessionTokens
) {
}
