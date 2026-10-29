package com.ecommerce.authuser.auth.application.google;

public class GoogleIdentityAlreadyLinkedException extends RuntimeException {

    public GoogleIdentityAlreadyLinkedException() {
        super("Google identity is linked to another account");
    }
}
