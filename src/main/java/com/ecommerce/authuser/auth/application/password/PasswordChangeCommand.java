package com.ecommerce.authuser.auth.application.password;

import java.util.UUID;

public record PasswordChangeCommand(
        UUID userId,
        UUID sessionId,
        String currentPassword,
        String newPassword,
        boolean allSessions,
        String stepUpToken,
        String clientIp
) {
}
