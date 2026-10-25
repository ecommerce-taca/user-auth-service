package com.ecommerce.authuser.shop.web.onboarding.get;

import com.ecommerce.authuser.shop.domain.KycStatus;
import com.ecommerce.authuser.shop.domain.OnboardingStep;
import com.ecommerce.authuser.shop.domain.ShopStatus;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GetSellerOnboardingResponse(
        Data data,
        Meta meta
) {

    public record Data(
            @JsonProperty("shop_id")
            UUID shopId,

            @JsonProperty("current_step")
            OnboardingStep currentStep,

            List<Step> steps,

            @JsonProperty("shop_status")
            ShopStatus shopStatus,

            @JsonProperty("kyc_status")
            KycStatus kycStatus,

            List<String> blockers,

            @JsonProperty("kyc_documents")
            List<KycDocument> kycDocuments
    ) {
    }

    public record Step(
            OnboardingStep key,
            boolean completed
    ) {
    }

    public record KycDocument(
            UUID id,

            @JsonProperty("document_type")
            String documentType,

            @JsonProperty("original_file_name")
            String originalFileName,

            @JsonProperty("content_type")
            String contentType,

            @JsonProperty("size_bytes")
            int sizeBytes,

            String status,

            @JsonProperty("uploaded_at")
            Instant uploadedAt,

            @JsonProperty("rejection_reason")
            String rejectionReason
    ) {
    }

    public record Meta(
            @JsonProperty("request_id")
            String requestId
    ) {
    }
}
