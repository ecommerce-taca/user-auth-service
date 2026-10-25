package com.ecommerce.authuser.kyc.application.complete;

import com.ecommerce.authuser.kyc.domain.KycCase;
import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.domain.KycDocumentStatus;

import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;
import com.ecommerce.authuser.kyc.exception.KycAlreadyPendingException;
import com.ecommerce.authuser.kyc.exception.KycDocumentAlreadyCompletedException;
import com.ecommerce.authuser.kyc.exception.KycDocumentNotFoundException;
import com.ecommerce.authuser.kyc.exception.KycDocumentTooLargeException;

import com.ecommerce.authuser.kyc.port.KycObjectStoragePort;

import com.ecommerce.authuser.kyc.repository.KycCaseRepository;
import com.ecommerce.authuser.kyc.repository.KycDocumentRepository;

import com.ecommerce.authuser.rbac.domain.RbacKeys;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;

import com.ecommerce.authuser.shop.domain.KycStatus;
import com.ecommerce.authuser.shop.domain.Shop;

import com.ecommerce.authuser.shop.exception.SellerPermissionDeniedException;
import com.ecommerce.authuser.shop.exception.ShopInvalidStateException;
import com.ecommerce.authuser.shop.exception.ShopNotFoundException;

import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.*;

@Service
@RequiredArgsConstructor
public class CompleteKycDocumentService {

    private static final long MAX_FILE_SIZE = 10L * 1024L * 1024L;

    private final ShopRepository shopRepository;

    private final UserRoleRepository userRoleRepository;

    private final KycCaseRepository kycCaseRepository;

    private final KycDocumentRepository kycDocumentRepository;

    private final KycObjectStoragePort kycObjectStoragePort;

    @Transactional
    public CompleteKycDocumentResult complete(CompleteKycDocumentCommand command) {
        if (command == null
                || command.userId() == null
                || command.documentId() == null) {

            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }

        Shop shop = shopRepository
                .findByOwnerIdForUpdate(command.userId())
                .orElseThrow(ShopNotFoundException::new);

        boolean sellerOwner = userRoleRepository
                .existsByUser_IdAndRole_RoleKeyAndShop_IdAndRevokedAtIsNull(
                        command.userId(),
                        RbacKeys.Roles.SELLER,
                        shop.getId()
                );

        if (!sellerOwner) {
            throw new SellerPermissionDeniedException();
        }

        if (!shop.canManageKycDocuments()) {
            throw new ShopInvalidStateException();
        }

        KycCase kycCase = kycCaseRepository
                .findCurrentByShopIdForUpdate(shop.getId())
                .orElseThrow(KycDocumentNotFoundException::new);

        validateCaseState(kycCase);

        KycDocument document = kycDocumentRepository
                .findByIdAndKycCaseIdForUpdate(command.documentId(), kycCase.getId())
                .orElseThrow(KycDocumentNotFoundException::new);

        validateDocumentState(document);

        String contentType = normalizeContentType(command.contentType());

        String sha256 = normalizeSha256(command.sha256());

        validateRequestAgainstDocument(
                command,
                document,
                contentType,
                sha256
        );

        KycObjectStoragePort.ObjectMetadata objectMetadata =
                kycObjectStoragePort
                        .findObjectMetadata(document.getObjectKey())
                        .orElseThrow(() -> new InvalidKycDocumentException(VERIFICATION_FAILED));

        validateStorageMetadata(document, objectMetadata);

        Instant now = Instant.now();

        document.markUploaded(now);

        kycDocumentRepository.saveAndFlush(document);

        return new CompleteKycDocumentResult(
                document.getId(),
                document.getStatus(),
                document.getUploadedAt()
        );
    }

    private void validateCaseState(KycCase kycCase) {
        KycStatus status = kycCase.getStatus();

        if (status == KycStatus.PENDING) {
            throw new KycAlreadyPendingException();
        }

        if (status == KycStatus.APPROVED
                || status == KycStatus.SUSPENDED) {

            throw new ShopInvalidStateException();
        }
    }

    private void validateDocumentState(KycDocument document) {
        KycDocumentStatus status = document.getStatus();

        if (status == KycDocumentStatus.UPLOADED
                || status == KycDocumentStatus.VERIFIED) {

            throw new KycDocumentAlreadyCompletedException();
        }

        if (status != KycDocumentStatus.UPLOADING) {
            throw new InvalidKycDocumentException(STATE_INVALID);
        }
    }

    private void validateRequestAgainstDocument(
            CompleteKycDocumentCommand command,
            KycDocument document,
            String contentType,
            String sha256
    ) {
        if (command.objectKey() == null
                || !command.objectKey().equals(document.getObjectKey()
        )) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }

        if (command.sizeBytes() < 1) {
            throw new InvalidKycDocumentException(SIZE_INVALID);
        }

        if (command.sizeBytes() > MAX_FILE_SIZE) {
            throw new KycDocumentTooLargeException();
        }

        if (command.sizeBytes() != document.getSizeBytes()) {

            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }

        if (!contentType.equals(document.getContentType())) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }

        if (!sha256.equals(document.getSha256())) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }
    }

    private void validateStorageMetadata(
            KycDocument document,
            KycObjectStoragePort.ObjectMetadata metadata
    ) {

        if (metadata.sizeBytes() != document.getSizeBytes()) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }

        if (metadata.contentType() == null
                || !metadata.contentType().equals(document.getContentType())) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }

        if (metadata.sha256() == null
                || !metadata.sha256().equals(document.getSha256())) {
            throw new InvalidKycDocumentException(VERIFICATION_FAILED);
        }
    }

    private String normalizeContentType(String value) {
        if (value == null) {
            throw new InvalidKycDocumentException(CONTENT_TYPE_UNSUPPORTED);
        }

        String normalized = value
                .strip()
                .toLowerCase(Locale.ROOT);

        if (!normalized.equals("application/pdf")
                && !normalized.equals("image/jpeg")
                && !normalized.equals("image/png")) {
            throw new InvalidKycDocumentException(CONTENT_TYPE_UNSUPPORTED);
        }

        return normalized;
    }

    private String normalizeSha256(String value) {
        if (value == null) {
            throw new InvalidKycDocumentException(CHECKSUM_INVALID);
        }

        String normalized = value
                .strip()
                .toLowerCase(Locale.ROOT);

        if (!normalized.matches("^[0-9a-f]{64}$")) {
            throw new InvalidKycDocumentException(CHECKSUM_INVALID);
        }

        return normalized;
    }
}
