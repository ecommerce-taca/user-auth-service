package com.ecommerce.authuser.auth.google;

public class GoogleSigninUnavailableException extends RuntimeException {

    public GoogleSigninUnavailableException() {
        super("Google sign-in is not configured");
    }
}
