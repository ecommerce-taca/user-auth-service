package com.ecommerce.authuser.kyc.web.presign;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.kyc.application.presign.PresignKycDocumentCommand;
import com.ecommerce.authuser.kyc.application.presign.PresignKycDocumentResult;
import com.ecommerce.authuser.kyc.application.presign.PresignKycDocumentService;

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
public class PresignKycDocumentController {

    private final PresignKycDocumentService presignKycDocumentService;

    @PostMapping("/presign")
    public ResponseEntity<PresignKycDocumentResponse> presign(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody PresignKycDocumentRequest request,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        if (request.invalid()) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }

        UUID userId =
                UUID.fromString(
                        jwt.getSubject()
                );

        PresignKycDocumentResult result =
                presignKycDocumentService.presign(
                        new PresignKycDocumentCommand(
                                userId,
                                request.documentType(),
                                request.fileName(),
                                request.contentType(),
                                request.sizeBytes(),
                                request.sha256()
                        )
                );

        PresignKycDocumentResponse response =
                new PresignKycDocumentResponse(
                        new PresignKycDocumentResponse.Data(
                                result.documentId(),
                                result.objectKey(),
                                result.uploadUrl(),
                                result.expiresAt(),
                                result.requiredHeaders()
                        ),

                        new PresignKycDocumentResponse.Meta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }
}
