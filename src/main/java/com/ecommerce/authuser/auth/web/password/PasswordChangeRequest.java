package com.ecommerce.authuser.auth.web.password;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PasswordChangeRequest(
        @JsonProperty("current_password")
        @NotBlank(message = "current_password is required")
        @Size(max = 72, message = "current_password is too long")
        String currentPassword,

        @JsonProperty("new_password")
        @NotBlank(message = "new_password is required")
        @Size(min = 12, max = 72, message = "new_password must be between 12 and 72 characters")
        String newPassword,

        @JsonProperty("all_sessions")
        Boolean allSessions
) {

    public boolean resolvedAllSessions() {
        return Boolean.TRUE.equals(allSessions);
    }
}
