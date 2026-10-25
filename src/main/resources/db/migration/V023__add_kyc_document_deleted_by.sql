ALTER TABLE kyc_documents
    ADD COLUMN deleted_by BINARY(16) NULL AFTER deleted_at,
    ADD CONSTRAINT fk_kyc_documents_deleted_by
        FOREIGN KEY (deleted_by)
        REFERENCES users(id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT;
