package com.ecommerce.authuser.auth.exception.password;

public class InvalidCurrentPasswordException extends RuntimeException {

    public InvalidCurrentPasswordException() {
        super("Current password is invalid");
    }
}
