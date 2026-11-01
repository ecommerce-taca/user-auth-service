package com.ecommerce.authuser.auth.web.mfa;

import com.ecommerce.authuser.auth.exception.mfa.MfaAuthenticationRequiredException;
import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.common.web.RequestMeta;
import com.ecommerce.authuser.mfa.application.admin.AdminStepUpService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.UUID;

/**
 * Lets the API Gateway verify an opaque {@code X-MFA-Step-Up} token before forwarding an admin
 * mutation to a service that cannot verify it itself (Search, Payment-Wallet). The Gateway calls
 * this with the caller's own bearer token; on 200 it sends {@code X-MFA-Step-Up: true} upstream,
 * otherwise it returns this endpoint's {@code 428 RBAC_MFA_REQUIRED} (with a fresh challenge) to
 * the client. Validation is the same as for auth-user's own admin mutations
 * ({@link AdminStepUpService#require}). CONTRACT-MATRIX C16.
 */
@RestController
@RequestMapping("/api/v1/auth/2fa/step-up")
@RequiredArgsConstructor
public class MfaStepUpCheckController {

    private final AdminStepUpService adminStepUpService;

    @PostMapping("/check")
    public ResponseEntity<MfaStepUpCheckResponse> check(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader(name = "X-MFA-Step-Up", required = false) String stepUpToken,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {
        if (jwt == null) {
            throw new MfaAuthenticationRequiredException();
        }

        UUID userId;
        UUID sessionId;
        try {
            userId = UUID.fromString(jwt.getSubject());
            sessionId = UUID.fromString(jwt.getClaimAsString("session_id"));
        } catch (RuntimeException ex) {
            throw new MfaAuthenticationRequiredException();
        }

        adminStepUpService.require(userId, sessionId, stepUpToken, Instant.now());

        return ResponseEntity
                .ok()
                .header("Cache-Control", "no-store")
                .body(new MfaStepUpCheckResponse(
                        new MfaStepUpCheckResponse.Data(true),
                        new RequestMeta(RequestIdResolver.resolve(requestId))
                ));
    }
}
