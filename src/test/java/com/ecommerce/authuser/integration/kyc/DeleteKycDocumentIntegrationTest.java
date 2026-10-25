package com.ecommerce.authuser.integration.kyc;

import com.ecommerce.authuser.audit.domain.AuditTargetType;
import com.ecommerce.authuser.audit.repository.AuditLogRepository;
import com.ecommerce.authuser.kyc.domain.KycCase;
import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.domain.KycDocumentStatus;
import com.ecommerce.authuser.kyc.repository.KycCaseRepository;
import com.ecommerce.authuser.kyc.repository.KycDocumentRepository;
import com.ecommerce.authuser.outbox.domain.OutboxAggregateType;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class DeleteKycDocumentIntegrationTest extends BaseIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private ShopRepository shopRepository;
    @Autowired private SellerOnboardingRepository sellerOnboardingRepository;
    @Autowired private KycCaseRepository kycCaseRepository;
    @Autowired private KycDocumentRepository kycDocumentRepository;
    @Autowired private AuditLogRepository auditLogRepository;

    @Test
    void delete_shouldSoftDeleteHideFromOnboardingAndWriteAuditAndOutbox() throws Exception {
        SellerContext seller = createSeller();
        KycDocument document = createDocument(seller.shop());

        mockMvc.perform(delete(endpoint(document))
                        .header("Authorization", "Bearer " + seller.token().value()))
                .andExpect(status().isNoContent());

        KycDocument persisted = kycDocumentRepository.findById(document.getId()).orElseThrow();
        assertThat(persisted.getStatus()).isEqualTo(KycDocumentStatus.DELETED);
        assertThat(persisted.getDeletedAt()).isNotNull();
        assertThat(persisted.getDeletedBy()).isEqualTo(seller.user().getId());

        assertThat(auditLogRepository
                .findAllByTargetTypeAndTargetIdOrderByOccurredAtDesc(
                        AuditTargetType.KYC, document.getId(), org.springframework.data.domain.Pageable.unpaged())
                .getContent())
                .anySatisfy(audit -> assertThat(audit.getAction()).isEqualTo("KYC_DOCUMENT_DELETED"));

        assertThat(outboxEventRepository
                .findAllByAggregateTypeAndAggregateIdOrderByCreatedAtAsc(
                        OutboxAggregateType.KYC, document.getId()))
                .anySatisfy(event -> assertThat(event.getEventType())
                        .isEqualTo("kyc.document.delete_requested"));

        mockMvc.perform(get("/api/v1/seller/onboarding")
                        .header("Authorization", "Bearer " + seller.token().value()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.kyc_documents").isEmpty());

        mockMvc.perform(delete(endpoint(document))
                        .header("Authorization", "Bearer " + seller.token().value()))
                .andExpect(status().isNoContent());
    }

    @Test
    void delete_shouldRejectPendingKycCase() throws Exception {
        SellerContext seller = createSeller();
        KycDocument document = createDocument(seller.shop());
        KycCase kycCase = document.getKycCase();
        Instant now = Instant.now();
        kycCase.submit(now, now.plusSeconds(3600));
        seller.shop().markKycPending();
        kycCaseRepository.saveAndFlush(kycCase);
        shopRepository.saveAndFlush(seller.shop());

        mockMvc.perform(delete(endpoint(document))
                        .header("Authorization", "Bearer " + seller.token().value()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("KYC_DOCUMENT_DELETE_NOT_ALLOWED"))
                .andExpect(jsonPath("$.error.details.kyc_status").value("PENDING"));

        assertThat(kycDocumentRepository.findById(document.getId()).orElseThrow().isDeleted()).isFalse();
    }

    @Test
    void delete_shouldNotRevealOtherSellersDocument() throws Exception {
        SellerContext sellerA = createSeller();
        SellerContext sellerB = createSeller();
        KycDocument documentB = createDocument(sellerB.shop());

        mockMvc.perform(delete(endpoint(documentB))
                        .header("Authorization", "Bearer " + sellerA.token().value()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("KYC_DOCUMENT_NOT_FOUND"));

        assertThat(kycDocumentRepository.findById(documentB.getId()).orElseThrow().isDeleted()).isFalse();
    }

    @Test
    void delete_shouldRejectInvalidDocumentId() throws Exception {
        SellerContext seller = createSeller();

        mockMvc.perform(delete("/api/v1/seller/onboarding/kyc/documents/not-a-uuid")
                        .header("Authorization", "Bearer " + seller.token().value()))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.error.details.field").value("documentId"));
    }

    private KycDocument createDocument(Shop shop) {
        KycCase kycCase = kycCaseRepository.saveAndFlush(
                KycCaseTestBuilder.aKycCase().forShop(shop).build());
        KycDocument document = KycDocumentTestBuilder.aKycDocument()
                .forKycCase(kycCase)
                .withObjectKey("private/kyc/" + UUID.randomUUID() + ".pdf")
                .withSha256(UUID.randomUUID().toString().replace("-", "")
                        + UUID.randomUUID().toString().replace("-", ""))
                .build();
        document.markUploaded(Instant.now());
        return kycDocumentRepository.saveAndFlush(document);
    }

    private SellerContext createSeller() {
        String unique = UUID.randomUUID().toString();
        User user = userRepository.saveAndFlush(UserTestBuilder.aUser()
                .withEmail("delete-kyc-" + unique + "@test.com")
                .withFullName("Delete KYC Seller")
                .build());
        Shop shop = shopRepository.saveAndFlush(ShopTestBuilder.forOwner(user)
                .withSlug("delete-kyc-" + unique)
                .build());
        sellerOnboardingRepository.saveAndFlush(SellerOnboarding.create(shop));
        Role sellerRole = roleRepository.findByRoleKey(RbacKeys.Roles.SELLER).orElseThrow();
        userRoleRepository.saveAndFlush(UserRole.assign(user, sellerRole, shop, user.getId()));
        return new SellerContext(user, shop, TestJwtFactory.createUserToken(
                user.getId(), List.of(RbacKeys.Roles.SELLER)));
    }

    private String endpoint(KycDocument document) {
        return "/api/v1/seller/onboarding/kyc/documents/" + document.getId();
    }

    private record SellerContext(User user, Shop shop, TestUserToken token) {
    }
}
