package com.ecommerce.authuser.integration.shop;

import com.ecommerce.authuser.kyc.domain.KycCase;
import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.repository.KycCaseRepository;
import com.ecommerce.authuser.kyc.repository.KycDocumentRepository;
import com.ecommerce.authuser.rbac.domain.RbacKeys;
import com.ecommerce.authuser.rbac.domain.Role;
import com.ecommerce.authuser.rbac.domain.UserRole;
import com.ecommerce.authuser.shop.domain.SellerOnboarding;
import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.repository.SellerOnboardingRepository;
import com.ecommerce.authuser.shop.repository.ShopRepository;
import com.ecommerce.authuser.support.base.BaseIntegrationTest;
import com.ecommerce.authuser.support.builder.KycCaseTestBuilder;
import com.ecommerce.authuser.support.builder.KycDocumentTestBuilder;
import com.ecommerce.authuser.support.builder.ShopTestBuilder;
import com.ecommerce.authuser.support.builder.UserTestBuilder;
import com.ecommerce.authuser.support.security.TestJwtFactory;
import com.ecommerce.authuser.support.security.TestUserToken;
import com.ecommerce.authuser.user.domain.User;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GetSellerOnboardingKycDocumentsIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ShopRepository shopRepository;

    @Autowired
    private SellerOnboardingRepository sellerOnboardingRepository;

    @Autowired
    private KycCaseRepository kycCaseRepository;

    @Autowired
    private KycDocumentRepository kycDocumentRepository;

    @Test
    void getOnboarding_shouldReturnKycDocumentsUsingFrontendContract() throws Exception {
        SellerContext seller = createSeller();

        KycCase kycCase = kycCaseRepository.saveAndFlush(
                KycCaseTestBuilder
                        .aKycCase()
                        .forShop(seller.shop())
                        .build()
        );

        KycDocument olderPdf = KycDocumentTestBuilder
                .aKycDocument()
                .forKycCase(kycCase)
                .withDocumentType("BUSINESS_REGISTRATION")
                .withObjectKey("private/kyc/older-" + UUID.randomUUID() + ".pdf")
                .withOriginalFileName("older.pdf")
                .withSha256("a".repeat(64))
                .build();
        olderPdf.markUploaded(Instant.parse("2026-10-24T10:15:30Z"));
        kycDocumentRepository.saveAndFlush(olderPdf);

        KycDocument newerImage = KycDocumentTestBuilder
                .aKycDocument()
                .forKycCase(kycCase)
                .withDocumentType("BUSINESS_REGISTRATION")
                .withObjectKey("private/kyc/newer-" + UUID.randomUUID() + ".png")
                .withOriginalFileName("newer.png")
                .withContentType("image/png")
                .withSha256("b".repeat(64))
                .build();
        newerImage.markUploaded(Instant.parse("2026-10-25T10:15:30Z"));
        kycDocumentRepository.saveAndFlush(newerImage);

        KycDocument pendingUpload = KycDocumentTestBuilder
                .aKycDocument()
                .forKycCase(kycCase)
                .withDocumentType("BUSINESS_REGISTRATION")
                .withObjectKey("private/kyc/pending-" + UUID.randomUUID() + ".jpg")
                .withOriginalFileName("pending.jpg")
                .withContentType("image/jpeg")
                .withSha256("c".repeat(64))
                .build();
        kycDocumentRepository.saveAndFlush(pendingUpload);

        KycDocument deleted = KycDocumentTestBuilder
                .aKycDocument()
                .forKycCase(kycCase)
                .withDocumentType("BUSINESS_REGISTRATION")
                .withObjectKey("private/kyc/deleted-" + UUID.randomUUID() + ".pdf")
                .withOriginalFileName("deleted.pdf")
                .withSha256("d".repeat(64))
                .build();
        deleted.softDelete(Instant.now());
        kycDocumentRepository.saveAndFlush(deleted);

        mockMvc.perform(
                        get("/api/v1/seller/onboarding")
                                .header(
                                        "Authorization",
                                        "Bearer " + seller.token().value()
                                )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.shop_id")
                        .value(seller.shop().getId().toString()))
                .andExpect(jsonPath("$.data.current_step").exists())
                .andExpect(jsonPath("$.data.steps").isArray())
                .andExpect(jsonPath("$.data.blockers").isArray())
                .andExpect(jsonPath("$.data.kyc_documents.length()").value(3))
                .andExpect(jsonPath("$.data.kyc_documents[0].id")
                        .value(newerImage.getId().toString()))
                .andExpect(jsonPath("$.data.kyc_documents[0].document_type")
                        .value("BUSINESS_REGISTRATION"))
                .andExpect(jsonPath("$.data.kyc_documents[0].original_file_name")
                        .value("newer.png"))
                .andExpect(jsonPath("$.data.kyc_documents[0].content_type")
                        .value("image/png"))
                .andExpect(jsonPath("$.data.kyc_documents[0].size_bytes").isNumber())
                .andExpect(jsonPath("$.data.kyc_documents[0].status")
                        .value("UPLOADED"))
                .andExpect(jsonPath("$.data.kyc_documents[0].uploaded_at")
                        .value("2026-10-25T10:15:30Z"))
                .andExpect(jsonPath("$.data.kyc_documents[1].id")
                        .value(olderPdf.getId().toString()))
                .andExpect(jsonPath("$.data.kyc_documents[2].status")
                        .value("PENDING_UPLOAD"));
    }

    @Test
    void getOnboarding_shouldReturnEmptyKycDocumentsWhenNoCaseExists() throws Exception {
        SellerContext seller = createSeller();

        mockMvc.perform(
                        get("/api/v1/seller/onboarding")
                                .header(
                                        "Authorization",
                                        "Bearer " + seller.token().value()
                                )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.kyc_documents").isArray())
                .andExpect(jsonPath("$.data.kyc_documents").isEmpty());
    }

    private SellerContext createSeller() {
        String unique = UUID.randomUUID().toString();

        User seller = UserTestBuilder
                .aUser()
                .withEmail("onboarding-kyc-" + unique + "@test.com")
                .withFullName("Onboarding KYC Seller")
                .build();
        seller = userRepository.saveAndFlush(seller);

        Shop shop = ShopTestBuilder
                .forOwner(seller)
                .withSlug("onboarding-kyc-" + unique)
                .build();
        shop = shopRepository.saveAndFlush(shop);

        sellerOnboardingRepository.saveAndFlush(
                SellerOnboarding.create(shop)
        );

        Role sellerRole = roleRepository
                .findByRoleKey(RbacKeys.Roles.SELLER)
                .orElseThrow();

        userRoleRepository.saveAndFlush(
                UserRole.assign(
                        seller,
                        sellerRole,
                        shop,
                        seller.getId()
                )
        );

        TestUserToken token = TestJwtFactory.createUserToken(
                seller.getId(),
                List.of(RbacKeys.Roles.SELLER)
        );

        return new SellerContext(shop, token);
    }

    private record SellerContext(
            Shop shop,
            TestUserToken token
    ) {
    }
}
