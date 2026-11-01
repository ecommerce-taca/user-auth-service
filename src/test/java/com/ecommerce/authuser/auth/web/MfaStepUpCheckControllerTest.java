package com.ecommerce.authuser.auth.web;

import com.ecommerce.authuser.auth.exception.mfa.MfaAuthenticationRequiredException;
import com.ecommerce.authuser.auth.exception.mfa.MfaStepUpRequiredException;
import com.ecommerce.authuser.auth.web.mfa.MfaStepUpCheckController;
import com.ecommerce.authuser.mfa.application.admin.AdminStepUpService;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class MfaStepUpCheckControllerTest {

    private final AdminStepUpService stepUpService = mock(AdminStepUpService.class);

    private final MfaStepUpCheckController controller = new MfaStepUpCheckController(stepUpService);

    private final UUID userId = UUID.randomUUID();

    private final UUID sessionId = UUID.randomUUID();

    private Jwt jwt(Map<String, Object> claims) {
        return new Jwt("t", Instant.now(), Instant.now().plusSeconds(60), Map.of("alg", "RS256"), claims);
    }

    @Test
    void validTokenReturnsStepUpValid() {
        var response = controller.check(
                jwt(Map.of("sub", userId.toString(), "session_id", sessionId.toString())), "raw-token", "req-1");

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody().data().stepUpValid()).isTrue();
        verify(stepUpService).require(eq(userId), eq(sessionId), eq("raw-token"), any(Instant.class));
    }

    @Test
    void invalidTokenPropagatesStepUpRequired() {
        doThrow(new MfaStepUpRequiredException(UUID.randomUUID(), Instant.now(), List.of("TOTP")))
                .when(stepUpService).require(any(), any(), any(), any());

        assertThatThrownBy(() -> controller.check(
                jwt(Map.of("sub", userId.toString(), "session_id", sessionId.toString())), "bad", null))
                .isInstanceOf(MfaStepUpRequiredException.class);
    }

    @Test
    void missingSessionClaimIsUnauthenticated() {
        assertThatThrownBy(() -> controller.check(jwt(Map.of("sub", userId.toString())), "raw-token", null))
                .isInstanceOf(MfaAuthenticationRequiredException.class);
        verifyNoInteractions(stepUpService);
    }
}
