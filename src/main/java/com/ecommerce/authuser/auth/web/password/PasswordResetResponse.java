package com.ecommerce.authuser.auth.web.password;

import com.ecommerce.authuser.auth.web.common.AuthTokenData;
import com.ecommerce.authuser.common.web.RequestMeta;

public record PasswordResetResponse(
        Data data,
        RequestMeta meta
) {

    public record Data(
            AuthTokenData tokens
    ) {
    }
}
