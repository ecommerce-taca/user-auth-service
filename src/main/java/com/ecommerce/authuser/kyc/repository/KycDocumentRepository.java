package com.ecommerce.authuser.kyc.repository;

import com.ecommerce.authuser.kyc.domain.KycDocument;
import com.ecommerce.authuser.kyc.domain.KycDocumentStatus;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface KycDocumentRepository extends JpaRepository<KycDocument, UUID> {

    Optional<KycDocument> findByIdAndKycCase_Shop_IdAndDeletedAtIsNull(
            UUID documentId,
            UUID shopId
    );

    List<KycDocument> findAllByKycCase_IdAndDeletedAtIsNullOrderByCreatedAtAsc(
            UUID kycCaseId
    );

    long countByKycCase_IdAndDeletedAtIsNull(UUID kycCaseId);

    boolean existsByKycCase_IdAndStatusAndDeletedAtIsNull(
            UUID kycCaseId,
            KycDocumentStatus status
    );

    boolean existsByKycCase_IdAndStatusInAndDeletedAtIsNull(
            UUID kycCaseId,
            Collection<KycDocumentStatus> statuses
    );

    boolean existsByKycCase_IdAndDocumentTypeAndSha256AndDeletedAtIsNull(
            UUID kycCaseId,
            String documentType,
            String sha256
    );

    @Query("""
        select document.kycCase.id
        from KycDocument document
        where document.id = :documentId
            and document.kycCase.shop.id = :shopId
            and document.deletedAt is null
        """)
    Optional<UUID> findKycCaseIdByDocumentIdAndShopId(
            @Param("documentId") UUID documentId,
            @Param("shopId") UUID shopId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select document
        from KycDocument document
        where document.id = :documentId
            and document.kycCase.shop.id = :shopId
            and document.deletedAt is null
        """)
    Optional<KycDocument> findByIdAndShopIdForUpdate(
            @Param("documentId") UUID documentId,
            @Param("shopId") UUID shopId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select document
        from KycDocument document
        where document.id = :documentId
            and document.kycCase.shop.id = :shopId
        """)
    Optional<KycDocument> findByIdAndShopIdIncludingDeletedForUpdate(
            @Param("documentId") UUID documentId,
            @Param("shopId") UUID shopId
    );

    @Query("""
        select
            document.kycCase.id as kycCaseId,
            count(document.id) as documentCount
        from KycDocument document
        where document.kycCase.id in :caseIds
            and document.deletedAt is null
        group by document.kycCase.id
        """)
    List<CaseDocumentCount> countLiveDocumentsByCaseIds(
            @Param("caseIds") Collection<UUID> caseIds
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select document
        from KycDocument document
        where document.kycCase.id = :kycCaseId
            and document.deletedAt is null
        order by document.createdAt asc
        """)
    List<KycDocument> findAllLiveByKycCaseIdForUpdate(
            @Param("kycCaseId") UUID kycCaseId
    );

    interface CaseDocumentCount {
        UUID getKycCaseId();
        long getDocumentCount();
    }

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        select document
        from KycDocument document
        where document.id = :documentId
            and document.kycCase.id = :kycCaseId
            and document.deletedAt is null
        """)
    Optional<KycDocument> findByIdAndKycCaseIdForUpdate(
            @Param("documentId") UUID documentId,
            @Param("kycCaseId") UUID kycCaseId
    );

    List<KycDocument> findAllByKycCase_IdAndDeletedAtIsNull(
            UUID kycCaseId
    );
}
