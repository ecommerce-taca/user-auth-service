package com.ecommerce.authuser.auth.web.google;

import com.ecommerce.authuser.common.web.RequestMeta;
import com.fasterxml.jackson.annotation.JsonProperty;

public record GoogleIdentityLinkResponse(
        Data data,
        RequestMeta meta
) {
    public record Data(
            @JsonProperty("linked")
            boolean linked
    ) {
    }
}
