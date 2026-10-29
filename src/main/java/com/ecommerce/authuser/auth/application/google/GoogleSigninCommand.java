package com.ecommerce.authuser.auth.application.google;

public record GoogleSigninCommand(
        String idToken,
        String clientIp,
        String userAgent
) {
}
