package com.ecommerce.authuser.kyc.web.submit;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.kyc.application.submit.SubmitKycCommand;
import com.ecommerce.authuser.kyc.application.submit.SubmitKycResult;
import com.ecommerce.authuser.kyc.application.submit.SubmitKycService;

import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import tools.jackson.databind.JsonNode;

import java.util.UUID;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.REQUEST_INVALID;

@RestController
@RequestMapping("/api/v1/seller/onboarding/kyc")
@RequiredArgsConstructor
public class SubmitKycController {

    private final SubmitKycService submitKycService;

    @PostMapping("/submit")
    public ResponseEntity<SubmitKycResponse> submit(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody(required = false) JsonNode body,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        validateEmptyBody(body);

        UUID userId = parseUuid(jwt.getSubject());

        SubmitKycResult result =
                submitKycService.submit(
                        new SubmitKycCommand(
                                userId
                        )
                );

        SubmitKycResponse response =
                new SubmitKycResponse(
                        new SubmitKycResponse.Data(
                                result.shopId(),
                                result.kycCaseId(),
                                result.status(),
                                result.submittedAt()
                        ),

                        new SubmitKycResponse.Meta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity.ok(
                response
        );
    }

    private void validateEmptyBody(JsonNode body) {
        if (body == null || body.isNull()) {
            return;
        }

        if (!body.isObject() || body.size() != 0) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }
    }

    private UUID parseUuid(String value) {

        try {
            return UUID.fromString(value);

        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }
    }
}
