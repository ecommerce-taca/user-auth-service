package com.ecommerce.authuser.auth.application.google;

import java.util.List;
import java.util.UUID;

public record GoogleSigninResult(
        UUID userId,
        String fullName,
        String email,
        boolean emailVerified,
        String phone,
        boolean phoneVerified,
        List<String> roles,
        String status,
        boolean created,
        String accessToken,
        long accessExpiresIn,
        String refreshToken,
        long refreshExpiresIn
) {
}
