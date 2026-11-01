package com.ecommerce.authuser.auth.web.mfa;

import com.ecommerce.authuser.common.web.RequestMeta;
import com.fasterxml.jackson.annotation.JsonProperty;

public record MfaStepUpCheckResponse(
        Data data,
        RequestMeta meta
) {

    public record Data(
            @JsonProperty("step_up_valid")
            boolean stepUpValid
    ) {
    }
}
