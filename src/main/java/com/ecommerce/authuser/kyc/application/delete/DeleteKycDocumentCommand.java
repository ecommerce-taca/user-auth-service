package com.ecommerce.authuser.kyc.application.delete;

import java.util.UUID;

public record DeleteKycDocumentCommand(
        UUID userId,
        UUID documentId
) {
}
