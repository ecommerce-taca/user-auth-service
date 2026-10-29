package com.ecommerce.authuser.auth.google;

public record GoogleIdentity(
        String subject,
        String email,
        String fullName
) {
}
