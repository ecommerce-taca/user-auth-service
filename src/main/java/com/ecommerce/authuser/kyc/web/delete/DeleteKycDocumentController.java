package com.ecommerce.authuser.kyc.web.delete;

import com.ecommerce.authuser.kyc.application.delete.DeleteKycDocumentCommand;
import com.ecommerce.authuser.kyc.application.delete.DeleteKycDocumentService;
import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentIdException;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/seller/onboarding/kyc/documents")
@RequiredArgsConstructor
public class DeleteKycDocumentController {

    private final DeleteKycDocumentService deleteKycDocumentService;

    @DeleteMapping("/{documentId}")
    public ResponseEntity<Void> delete(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable String documentId
    ) {
        deleteKycDocumentService.delete(new DeleteKycDocumentCommand(
                UUID.fromString(jwt.getSubject()),
                parseDocumentId(documentId)
        ));

        return ResponseEntity.noContent().build();
    }

    private UUID parseDocumentId(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new InvalidKycDocumentIdException();
        }
    }
}
