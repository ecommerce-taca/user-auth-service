package com.ecommerce.authuser.auth.web.google;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record GoogleIdentityLinkRequest(
        @JsonProperty("id_token")
        @NotBlank
        @Size(max = 16384)
        String idToken
) {
}
