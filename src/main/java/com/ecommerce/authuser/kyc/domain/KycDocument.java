package com.ecommerce.authuser.kyc.domain;

import com.ecommerce.authuser.common.id.UuidV7Generator;

import jakarta.persistence.*;

import lombok.Getter;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(name = "kyc_documents")
public class KycDocument {

    private static final int MAX_FILE_SIZE = 10 * 1024 * 1024;

    @Id
    @Column(
            name = "id",
            nullable = false,
            updatable = false,
            columnDefinition = "BINARY(16)"
    )
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "kyc_case_id", nullable = false)
    private KycCase kycCase;

    @Column(name = "document_type", nullable = false, length = 32)
    private String documentType;

    @Column(name = "object_key", nullable = false, length = 512)
    private String objectKey;

    @Column(name = "original_file_name", nullable = false, length = 255)
    private String originalFileName;

    @Column(name = "content_type", nullable = false, length = 64)
    private String contentType;

    @Column(name = "size_bytes", nullable = false, columnDefinition = "INT UNSIGNED")
    private int sizeBytes;

    @Column(
            name = "sha256",
            nullable = false,
            length = 64,
            columnDefinition = "CHAR(64)"
    )
    private String sha256;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private KycDocumentStatus status;

    @Column(name = "uploaded_at")
    private Instant uploadedAt;

    @Column(name = "verified_at")
    private Instant verifiedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    @Column(name = "deleted_by", columnDefinition = "BINARY(16)")
    private UUID deletedBy;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected KycDocument() {
    }

    public static KycDocument createUploading(
            KycCase kycCase,
            String documentType,
            String objectKey,
            String originalFileName,
            String contentType,
            int sizeBytes,
            String sha256
    ) {
        Objects.requireNonNull(kycCase);
        Objects.requireNonNull(documentType);
        Objects.requireNonNull(objectKey);
        Objects.requireNonNull(originalFileName);
        Objects.requireNonNull(contentType);
        Objects.requireNonNull(sha256);

        String normalizedDocumentType = documentType.trim();

        String normalizedContentType =
                contentType.trim().toLowerCase(Locale.ROOT);

        String normalizedSha256 =
                sha256.trim().toLowerCase(Locale.ROOT);

        if (normalizedDocumentType.isEmpty() || normalizedDocumentType.length() > 32) {
            throw new IllegalArgumentException(
                    "Invalid documentType"
            );
        }

        if (objectKey.isBlank() || objectKey.length() > 512) {
            throw new IllegalArgumentException(
                    "Invalid objectKey"
            );
        }

        if (originalFileName.isBlank() || originalFileName.length() > 255) {
            throw new IllegalArgumentException(
                    "Invalid originalFileName"
            );
        }

        if (!isSupportedContentType(normalizedContentType)) {
            throw new IllegalArgumentException(
                    "Unsupported content type"
            );
        }

        if (sizeBytes < 1 || sizeBytes > MAX_FILE_SIZE) {
            throw new IllegalArgumentException(
                    "Invalid file size"
            );
        }

        if (!normalizedSha256.matches("^[0-9a-f]{64}$")) {
            throw new IllegalArgumentException(
                    "Invalid SHA-256 checksum"
            );
        }

        KycDocument document = new KycDocument();

        document.id = UuidV7Generator.generate();
        document.kycCase = kycCase;
        document.documentType = normalizedDocumentType;
        document.objectKey = objectKey;
        document.originalFileName = originalFileName;
        document.contentType = normalizedContentType;
        document.sizeBytes = sizeBytes;
        document.sha256 = normalizedSha256;
        document.status = KycDocumentStatus.UPLOADING;

        return document;
    }

    private static boolean isSupportedContentType(
            String contentType
    ) {
        return contentType.equals("application/pdf")
                || contentType.equals("image/jpeg")
                || contentType.equals("image/png");
    }

    public void markUploaded(Instant now) {
        Objects.requireNonNull(now);

        if (status != KycDocumentStatus.UPLOADING) {
            throw new IllegalStateException(
                    "Only UPLOADING document can be completed"
            );
        }

        status = KycDocumentStatus.UPLOADED;

        uploadedAt = now;
    }

    public void markVerified(Instant now) {
        Objects.requireNonNull(now);

        if (status != KycDocumentStatus.UPLOADED) {
            throw new IllegalStateException(
                    "Only UPLOADED document can be verified"
            );
        }

        status = KycDocumentStatus.VERIFIED;

        verifiedAt = now;
    }

    public void reject() {
        if (status != KycDocumentStatus.UPLOADED
                && status != KycDocumentStatus.VERIFIED
        ) {
            throw new IllegalStateException(
                    "Document cannot be rejected from "
                            + status
            );
        }

        status = KycDocumentStatus.REJECTED;
    }

    public void softDelete(Instant now, UUID actorUserId) {
        Objects.requireNonNull(now);
        Objects.requireNonNull(actorUserId);

        if (deletedAt != null) {
            return;
        }

        deletedAt = now;
        deletedBy = actorUserId;

        status = KycDocumentStatus.DELETED;
    }

    public void softDelete(Instant now) {
        Objects.requireNonNull(now);

        if (deletedAt != null) {
            return;
        }

        deletedAt = now;
        status = KycDocumentStatus.DELETED;
    }

    public boolean isDeleted() {
        return deletedAt != null;
    }

    @PrePersist
    private void prePersist() {
        Instant now = Instant.now();

        if (createdAt == null) {
            createdAt = now;
        }

        if (updatedAt == null) {
            updatedAt = now;
        }
    }

    @PreUpdate
    private void preUpdate() {
        updatedAt = Instant.now();
    }
}
