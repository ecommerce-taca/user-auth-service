package com.ecommerce.authuser.shop.application.onboarding.get;

import com.ecommerce.authuser.kyc.domain.KycCase;
import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.domain.KycDocumentStatus;
import com.ecommerce.authuser.kyc.repository.KycCaseRepository;
import com.ecommerce.authuser.kyc.repository.KycDocumentRepository;
import com.ecommerce.authuser.rbac.domain.RbacKeys;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;

import com.ecommerce.authuser.shop.domain.OnboardingStep;
import com.ecommerce.authuser.shop.domain.SellerOnboarding;
import com.ecommerce.authuser.shop.domain.Shop;

import com.ecommerce.authuser.shop.exception.SellerPermissionDeniedException;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;

import com.ecommerce.authuser.shop.repository.SellerOnboardingRepository;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;

@Service
@RequiredArgsConstructor
public class GetSellerOnboardingService {

    private final ShopRepository shopRepository;

    private final SellerOnboardingRepository sellerOnboardingRepository;

    private final UserRoleRepository userRoleRepository;

    private final KycCaseRepository kycCaseRepository;

    private final KycDocumentRepository kycDocumentRepository;

    @Transactional(readOnly = true)
    public GetSellerOnboardingResult get(
            GetSellerOnboardingQuery query
    ) {

        if (query == null || query.userId() == null) {
            throw new ShopNotFoundException();
        }

        Shop shop = shopRepository
                .findByOwner_IdAndDeletedAtIsNull(query.userId())
                .orElseThrow(ShopNotFoundException::new);

        boolean sellerOwner = userRoleRepository
                .existsByUser_IdAndRole_RoleKeyAndShop_IdAndRevokedAtIsNull(
                        query.userId(),
                        RbacKeys.Roles.SELLER,
                        shop.getId()
                );

        if (!sellerOwner) {
            throw new SellerPermissionDeniedException();
        }

        SellerOnboarding onboarding = sellerOnboardingRepository
                .findByShop_Id(shop.getId())
                .orElseThrow(ShopNotFoundException::new);

        List<GetSellerOnboardingResult.StepResult> steps =
                List.of(
                        new GetSellerOnboardingResult.StepResult(
                                OnboardingStep.PROFILE,
                                onboarding.isProfileCompleted()
                        ),

                        new GetSellerOnboardingResult.StepResult(
                                OnboardingStep.KYC,
                                onboarding.isKycCompleted()
                        ),

                        new GetSellerOnboardingResult.StepResult(
                                OnboardingStep.WAREHOUSE,
                                onboarding.isWarehouseCompleted()
                        ),

                        new GetSellerOnboardingResult.StepResult(
                                OnboardingStep.BANK,
                                onboarding.isBankCompleted()
                        ),

                        new GetSellerOnboardingResult.StepResult(
                                OnboardingStep.FIRST_PRODUCT,
                                onboarding.isFirstProductCompleted()
                        )
                );

        List<GetSellerOnboardingResult.KycDocumentResult> kycDocuments =
                loadKycDocuments(shop);

        return new GetSellerOnboardingResult(
                shop.getId(),
                onboarding.getCurrentStep(),
                steps,
                shop.getStatus(),
                shop.getKycStatus(),
                onboarding.getBlockers(),
                kycDocuments
        );
    }

    private List<GetSellerOnboardingResult.KycDocumentResult> loadKycDocuments(
            Shop shop
    ) {
        KycCase kycCase = kycCaseRepository
                .findFirstByShop_IdOrderBySourceVersionDesc(shop.getId())
                .orElse(null);

        if (kycCase == null) {
            return List.of();
        }

        Comparator<KycDocument> newestUploadedFirst =
                Comparator.comparing(
                                KycDocument::getUploadedAt,
                                Comparator.nullsLast(Comparator.reverseOrder())
                        )
                        .thenComparing(
                                KycDocument::getCreatedAt,
                                Comparator.reverseOrder()
                        );

        return kycDocumentRepository
                .findAllByKycCase_IdAndDeletedAtIsNullOrderByCreatedAtAsc(
                        kycCase.getId()
                )
                .stream()
                .sorted(newestUploadedFirst)
                .map(this::toKycDocumentResult)
                .toList();
    }

    private GetSellerOnboardingResult.KycDocumentResult toKycDocumentResult(
            KycDocument document
    ) {
        return new GetSellerOnboardingResult.KycDocumentResult(
                document.getId(),
                document.getDocumentType(),
                document.getOriginalFileName(),
                document.getContentType(),
                document.getSizeBytes(),
                toApiStatus(document.getStatus()),
                document.getUploadedAt(),
                null
        );
    }

    private String toApiStatus(KycDocumentStatus status) {
        return switch (status) {
            case UPLOADING -> "PENDING_UPLOAD";
            case UPLOADED -> "UPLOADED";
            case VERIFIED -> "VERIFIED";
            case REJECTED, EXPIRED -> "REJECTED";
            case DELETED -> throw new IllegalStateException(
                    "Deleted KYC document must not be exposed"
            );
        };
    }
}
