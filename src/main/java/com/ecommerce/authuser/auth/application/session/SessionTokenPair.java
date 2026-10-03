package com.ecommerce.authuser.auth.application.session;

public record SessionTokenPair(
        String accessToken,
        String refreshToken,
        long accessExpiresIn,
        long refreshExpiresIn
) {
}
