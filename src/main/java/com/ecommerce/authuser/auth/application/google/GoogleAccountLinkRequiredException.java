package com.ecommerce.authuser.auth.application.google;

public class GoogleAccountLinkRequiredException extends RuntimeException {

    public GoogleAccountLinkRequiredException() {
        super("An account with this email must be linked explicitly");
    }
}
