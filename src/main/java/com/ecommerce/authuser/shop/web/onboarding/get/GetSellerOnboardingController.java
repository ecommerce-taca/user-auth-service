package com.ecommerce.authuser.shop.web.onboarding.get;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.common.web.RequestIdResolver;
import com.ecommerce.authuser.shop.application.onboarding.get.GetSellerOnboardingQuery;
import com.ecommerce.authuser.shop.application.onboarding.get.GetSellerOnboardingResult;
import com.ecommerce.authuser.shop.application.onboarding.get.GetSellerOnboardingService;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/seller/onboarding")
@RequiredArgsConstructor
public class GetSellerOnboardingController {

    private final GetSellerOnboardingService getSellerOnboardingService;

    @GetMapping
    public ResponseEntity<GetSellerOnboardingResponse> getOnboarding(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader(name = "X-Request-ID", required = false) String requestId
    ) {

        UUID userId = UUID.fromString(jwt.getSubject());

        GetSellerOnboardingResult result =
                getSellerOnboardingService.get(
                        new GetSellerOnboardingQuery(
                                userId
                        )
                );

        List<GetSellerOnboardingResponse.Step> steps =
                result.steps()
                        .stream()
                        .map(step ->
                                new GetSellerOnboardingResponse.Step(
                                        step.key(),
                                        step.completed()
                                )
                        )
                        .toList();

        List<GetSellerOnboardingResponse.KycDocument> kycDocuments =
                result.kycDocuments()
                        .stream()
                        .map(document ->
                                new GetSellerOnboardingResponse.KycDocument(
                                        document.id(),
                                        document.documentType(),
                                        document.originalFileName(),
                                        document.contentType(),
                                        document.sizeBytes(),
                                        document.status(),
                                        document.uploadedAt(),
                                        document.rejectionReason()
                                )
                        )
                        .toList();

        GetSellerOnboardingResponse response =
                new GetSellerOnboardingResponse(
                        new GetSellerOnboardingResponse.Data(
                                result.shopId(),
                                result.currentStep(),
                                steps,
                                result.shopStatus(),
                                result.kycStatus(),
                                result.blockers(),
                                kycDocuments
                        ),
                        new GetSellerOnboardingResponse.Meta(
                                RequestIdResolver.resolve(requestId)
                        )
                );

        return ResponseEntity.ok(response);
    }
}
