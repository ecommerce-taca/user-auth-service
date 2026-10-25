package com.ecommerce.authuser.shop.application.onboarding.get;

import com.ecommerce.authuser.shop.domain.KycStatus;
import com.ecommerce.authuser.shop.domain.OnboardingStep;
import com.ecommerce.authuser.shop.domain.ShopStatus;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GetSellerOnboardingResult(
        UUID shopId,
        OnboardingStep currentStep,
        List<StepResult> steps,
        ShopStatus shopStatus,
        KycStatus kycStatus,
        List<String> blockers,
        List<KycDocumentResult> kycDocuments
) {

    public record StepResult(
            OnboardingStep key,
            boolean completed
    ) {
    }

    public record KycDocumentResult(
            UUID id,
            String documentType,
            String originalFileName,
            String contentType,
            int sizeBytes,
            String status,
            Instant uploadedAt,
            String rejectionReason
    ) {
    }
}
