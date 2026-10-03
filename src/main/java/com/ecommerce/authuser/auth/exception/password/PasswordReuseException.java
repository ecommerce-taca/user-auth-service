package com.ecommerce.authuser.auth.exception.password;

public class PasswordReuseException extends RuntimeException {

    public PasswordReuseException() {
        super("New password must differ from the current password");
    }
}
