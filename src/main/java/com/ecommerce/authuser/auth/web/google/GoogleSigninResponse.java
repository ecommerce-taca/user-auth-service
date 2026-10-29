package com.ecommerce.authuser.auth.web.google;

import com.ecommerce.authuser.auth.web.common.AuthTokenData;
import com.ecommerce.authuser.auth.web.signin.SigninResponse;
import com.ecommerce.authuser.common.web.RequestMeta;
import com.fasterxml.jackson.annotation.JsonProperty;

public record GoogleSigninResponse(
        Data data,
        RequestMeta meta
) {
    public record Data(
            SigninResponse.UserData user,
            AuthTokenData tokens,
            boolean created
    ) {
    }
}
