package com.ecommerce.authuser.token.domain;

public enum TokenRevokeReason {

    ROTATED,
    SIGNOUT,
    RESET,
    PASSWORD_CHANGE,
    REUSE,
    SUSPEND,
    EXPIRED
}
