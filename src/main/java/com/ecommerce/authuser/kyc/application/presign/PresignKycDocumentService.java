package com.ecommerce.authuser.kyc.application.presign;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import com.ecommerce.authuser.kyc.domain.KycCase;
import com.ecommerce.authuser.kyc.domain.KycDocument;

import com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException;
import com.ecommerce.authuser.kyc.exception.KycAlreadyPendingException;
import com.ecommerce.authuser.kyc.exception.KycDocumentLimitReachedException;
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

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.ecommerce.authuser.kyc.exception.InvalidKycDocumentException.Reason.*;

@Service
@RequiredArgsConstructor
public class PresignKycDocumentService {

    private static final long MAX_FILE_SIZE = 10L * 1024L * 1024L;

    private static final long MAX_DOCUMENTS_PER_CASE = 10L;

    private static final Duration PRESIGN_TTL = Duration.ofMinutes(10);


    private static final Set<String> SUPPORTED_DOCUMENT_TYPES =
            Set.of("BUSINESS_REGISTRATION");

    private final ShopRepository shopRepository;

    private final UserRoleRepository userRoleRepository;

    private final KycCaseRepository kycCaseRepository;

    private final KycDocumentRepository kycDocumentRepository;

    private final KycObjectStoragePort kycObjectStoragePort;

    @Transactional
    public PresignKycDocumentResult presign(PresignKycDocumentCommand command) {
        if (command == null || command.userId() == null) {
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

        String documentType = normalizeDocumentType(command.documentType());

        String fileName = sanitizeFileName(command.fileName());

        String contentType = normalizeContentType(command.contentType());

        long sizeBytes = validateSize(command.sizeBytes());

        String sha256 = normalizeSha256(command.sha256());

        KycCase kycCase = resolveEditableCase(shop);

        long documentCount = kycDocumentRepository
                .countByKycCase_IdAndDeletedAtIsNull(kycCase.getId());

        if (documentCount >= MAX_DOCUMENTS_PER_CASE) {
            throw new KycDocumentLimitReachedException();
        }

        if (kycDocumentRepository
                .existsByKycCase_IdAndDocumentTypeAndSha256AndDeletedAtIsNull(
                        kycCase.getId(),
                        documentType,
                        sha256
                )) {

            throw new InvalidKycDocumentException(DUPLICATE);
        }

        String objectKey = createObjectKey(
                shop.getId().toString(),
                contentType
        );

        KycDocument document;

        try {
            document = KycDocument.createUploading(
                    kycCase,
                    documentType,
                    objectKey,
                    fileName,
                    contentType,
                    (int) sizeBytes,
                    sha256
            );

        } catch (IllegalArgumentException ex) {
            throw new InvalidKycDocumentException(REQUEST_INVALID);
        }

        saveDocument(document);

        KycObjectStoragePort.PresignResult presignResult =
                kycObjectStoragePort
                        .presignUpload(
                                objectKey,
                                contentType,
                                sizeBytes,
                                sha256,
                                PRESIGN_TTL
                        );

        return new PresignKycDocumentResult(
                document.getId(),
                objectKey,
                presignResult.uploadUrl(),
                presignResult.expiresAt(),
                presignResult.requiredHeaders()
        );
    }

    private KycCase resolveEditableCase(Shop shop) {

        KycCase latest = kycCaseRepository
                .findCurrentByShopIdForUpdate(shop.getId())
                .orElse(null);

        if (latest == null) {
            return createDraftCase(shop, 1);
        }

        KycStatus status = latest.getStatus();

        if (status == KycStatus.PENDING) {
            throw new KycAlreadyPendingException();
        }

        if (status == KycStatus.APPROVED
                || status == KycStatus.SUSPENDED) {

            throw new ShopInvalidStateException();
        }

        if (status == KycStatus.DRAFT
                || status == KycStatus.NEEDS_INFO) {

            return latest;
        }

        if (status == KycStatus.REJECTED
                || status == KycStatus.EXPIRED) {

            int nextSourceVersion = nextSourceVersion(latest.getSourceVersion());

            return createDraftCase(
                    shop,
                    nextSourceVersion
            );
        }

        throw new ShopInvalidStateException();
    }

    private KycCase createDraftCase(
            Shop shop,
            int sourceVersion
    ) {

        KycCase newCase =
                KycCase.createDraft(
                        shop,
                        sourceVersion
                );

        return kycCaseRepository
                .saveAndFlush(
                        newCase
                );
    }

    private int nextSourceVersion(
            int current
    ) {

        if (current < 1
                || current == Integer.MAX_VALUE) {

            throw new ShopInvalidStateException();
        }

        return current + 1;
    }

    private String normalizeDocumentType(String value) {

        if (value == null) {
            throw new InvalidKycDocumentException(DOCUMENT_TYPE_UNSUPPORTED);
        }

        String normalized = value.strip();

        if (!SUPPORTED_DOCUMENT_TYPES.contains(normalized)) {
            throw new InvalidKycDocumentException(DOCUMENT_TYPE_UNSUPPORTED);
        }

        return normalized;
    }

    private String sanitizeFileName(String value) {
        if (value == null) {
            throw new InvalidKycDocumentException(FILE_NAME_INVALID);
        }

        String normalized = value
                .strip()
                .replace('\\', '/');

        int slashIndex = normalized.lastIndexOf('/');

        if (slashIndex >= 0) {
            normalized = normalized
                    .substring(slashIndex + 1)
                    .strip();
        }

        int length =
                normalized.codePointCount(0, normalized.length());

        if (length < 1
                || length > 255
                || normalized.equals(".")
                || normalized.equals("..")
                || containsControlCharacter(
                normalized
        )) {

            throw new InvalidKycDocumentException(FILE_NAME_INVALID);
        }

        return normalized;
    }

    private boolean containsControlCharacter(String value) {
        return value
                .codePoints()
                .anyMatch(Character::isISOControl);
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

    private long validateSize(long sizeBytes) {
        if (sizeBytes < 1) {
            throw new InvalidKycDocumentException(SIZE_INVALID);
        }

        if (sizeBytes > MAX_FILE_SIZE) {
            throw new KycDocumentTooLargeException();
        }

        return sizeBytes;
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

    private String createObjectKey(
            String shopId,
            String contentType
    ) {

        String extension =
                switch (contentType) {
                    case "application/pdf" ->
                            ".pdf";

                    case "image/jpeg" ->
                            ".jpg";

                    case "image/png" ->
                            ".png";

                    default -> throw new InvalidKycDocumentException(CONTENT_TYPE_UNSUPPORTED);
                };

        return "private/kyc/"
                + shopId
                + "/document-"
                + UuidV7Generator.generate()
                + extension;
    }

    private void saveDocument(KycDocument document) {
        try {
            kycDocumentRepository.saveAndFlush(document);

        } catch (DataIntegrityViolationException ex) {

            if (containsConstraint(ex, "uk_kyc_doc_checksum")) {
                throw new InvalidKycDocumentException(DUPLICATE);
            }

            throw ex;
        }
    }

    private boolean containsConstraint(
            Throwable throwable,
            String constraintName
    ) {

        Throwable current = throwable;

        while (current != null) {
            String message = current.getMessage();

            if (message != null && message.contains(constraintName)) {
                return true;
            }

            current = current.getCause();
        }

        return false;
    }
}
