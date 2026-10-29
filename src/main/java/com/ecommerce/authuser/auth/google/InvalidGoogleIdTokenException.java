package com.ecommerce.authuser.auth.google;

public class InvalidGoogleIdTokenException extends RuntimeException {

    public InvalidGoogleIdTokenException() {
        super("Google ID token is invalid");
    }

    public InvalidGoogleIdTokenException(Throwable cause) {
        super("Google ID token is invalid", cause);
    }
}
