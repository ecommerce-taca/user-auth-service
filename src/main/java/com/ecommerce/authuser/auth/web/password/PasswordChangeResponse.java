package com.ecommerce.authuser.auth.web.password;

import com.ecommerce.authuser.auth.web.common.AuthTokenData;
import com.ecommerce.authuser.common.web.RequestMeta;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record PasswordChangeResponse(
        Data data,
        RequestMeta meta
) {

    public record Data(
            @JsonProperty("all_sessions")
            boolean allSessions,

            @JsonProperty("sessions_revoked")
            long sessionsRevoked,

            AuthTokenData tokens
    ) {
    }
}
