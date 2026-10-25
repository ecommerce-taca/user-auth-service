package com.ecommerce.authuser.kyc.web.complete;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.kyc.application.complete.CompleteKycDocumentCommand;
import com.ecommerce.authuser.kyc.application.complete.CompleteKycDocumentResult;
import com.ecommerce.authuser.kyc.application.complete.CompleteKycDocumentService;

import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.REQUEST_INVALID;

@RestController
@RequestMapping("/api/v1/seller/onboarding/kyc/documents")
@RequiredArgsConstructor
public class CompleteKycDocumentController {

    private final CompleteKycDocumentService completeKycDocumentService;

    @PostMapping("/complete")
    public ResponseEntity<CompleteKycDocumentResponse> complete(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody CompleteKycDocumentRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        if (request.invalid()) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }

        UUID userId = parseUuid(jwt.getSubject());

        UUID documentId = parseUuid(request.documentId());

        CompleteKycDocumentResult result =
                completeKycDocumentService.complete(
                        new CompleteKycDocumentCommand(
                                userId,
                                documentId,
                                request.objectKey(),
                                request.sizeBytes(),
                                request.contentType(),
                                request.sha256()
                        )
                );

        CompleteKycDocumentResponse response =
                new CompleteKycDocumentResponse(
                        new CompleteKycDocumentResponse.Data(
                                result.documentId(),
                                result.status(),
                                result.uploadedAt()
                        ),

                        new CompleteKycDocumentResponse.Meta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }

    private UUID parseUuid(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }
    }
}
