package com.ecommerce.authuser.kyc.application.delete;

import com.ecommerce.authuser.audit.domain.AuditLog;
import com.ecommerce.authuser.audit.domain.AuditTargetType;
import com.ecommerce.authuser.audit.repository.AuditLogRepository;
import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.domain.KycDocumentStatus;
import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;
import com.ecommerce.authuser.kyc.exception.KycDocumentDeleteNotAllowedException;
import com.ecommerce.authuser.kyc.exception.KycDocumentNotFoundException;
import com.ecommerce.authuser.kyc.repository.KycDocumentRepository;
import com.ecommerce.authuser.outbox.domain.OutboxAggregateType;
import com.ecommerce.authuser.outbox.domain.OutboxEvent;
import com.ecommerce.authuser.outbox.repository.OutboxEventRepository;
import com.ecommerce.authuser.rbac.domain.RbacKeys;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;
import com.ecommerce.authuser.shop.domain.KycStatus;
import com.ecommerce.authuser.shop.domain.SellerOnboarding;
import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.exception.SellerPermissionDeniedException;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;
import com.ecommerce.authuser.shop.repository.SellerOnboardingRepository;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.REQUEST_INVALID;

@Service
@RequiredArgsConstructor
public class DeleteKycDocumentService {

    private static final short EVENT_SCHEMA_VERSION = 1;

    private final ShopRepository shopRepository;
    private final UserRoleRepository userRoleRepository;
    private final SellerOnboardingRepository sellerOnboardingRepository;
    private final KycDocumentRepository kycDocumentRepository;
    private final AuditLogRepository auditLogRepository;
    private final OutboxEventRepository outboxEventRepository;

    @Transactional
    public void delete(DeleteKycDocumentCommand command) {
        if (command == null || command.userId() == null || command.documentId() == null) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }

        Shop shop = shopRepository.findByOwnerIdForUpdate(command.userId())
                .orElseThrow(ShopNotFoundException::new);

        boolean sellerOwner = userRoleRepository
                .existsByUser_IdAndRole_RoleKeyAndShop_IdAndRevokedAtIsNull(
                        command.userId(), RbacKeys.Roles.SELLER, shop.getId()
                );
        if (!sellerOwner) {
            throw new SellerPermissionDeniedException();
        }

        KycDocument document = kycDocumentRepository
                .findByIdAndShopIdIncludingDeletedForUpdate(command.documentId(), shop.getId())
                .orElseThrow(KycDocumentNotFoundException::new);

        // A retry after a successful delete must be harmless, even if the case later changed state.
        if (document.isDeleted()) {
            return;
        }

        KycStatus kycStatus = document.getKycCase().getStatus();
        if (kycStatus != KycStatus.DRAFT
                && kycStatus != KycStatus.NEEDS_INFO
                && kycStatus != KycStatus.REJECTED) {
            throw new KycDocumentDeleteNotAllowedException(kycStatus);
        }

        SellerOnboarding onboarding = sellerOnboardingRepository
                .findByShopIdForUpdate(shop.getId())
                .orElseThrow(() -> new IllegalStateException("Seller onboarding not found for shop"));

        Instant now = Instant.now();
        document.softDelete(now, command.userId());
        kycDocumentRepository.saveAndFlush(document);

        boolean hasValidDocument = kycDocumentRepository
                .existsByKycCase_IdAndStatusInAndDeletedAtIsNull(
                        document.getKycCase().getId(),
                        List.of(KycDocumentStatus.UPLOADED, KycDocumentStatus.VERIFIED)
                );
        if (!hasValidDocument) {
            onboarding.reopenKycStep();
            sellerOnboardingRepository.saveAndFlush(onboarding);
        }

        auditLogRepository.save(AuditLog.create(
                command.userId(),
                "KYC_DOCUMENT_DELETED",
                AuditTargetType.KYC,
                document.getId(),
                null,
                Map.of(
                        "shop_id", shop.getId().toString(),
                        "document_id", document.getId().toString(),
                        "actor_user_id", command.userId().toString()
                ),
                null,
                now
        ));

        outboxEventRepository.save(OutboxEvent.createWithActor(
                OutboxAggregateType.KYC,
                document.getId(),
                command.userId(),
                "kyc.document.delete_requested",
                EVENT_SCHEMA_VERSION,
                shop.getId().toString(),
                Map.of(
                        "shop_id", shop.getId().toString(),
                        "document_id", document.getId().toString(),
                        "object_key", document.getObjectKey()
                )
        ));
    }
}
