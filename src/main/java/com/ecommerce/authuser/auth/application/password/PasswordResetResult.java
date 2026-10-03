package com.ecommerce.authuser.auth.application.password;

public record PasswordResetResult(
        String accessToken,
        String refreshToken,
        long accessExpiresIn,
        long refreshExpiresIn
) {
}
