ALTER TABLE users
    MODIFY password_hash VARCHAR(255) NULL;

CREATE TABLE external_identities
(
    id BINARY(16) NOT NULL,
    user_id BINARY(16) NOT NULL,
    provider VARCHAR(32) NOT NULL,
    provider_subject VARCHAR(255) NOT NULL,
    provider_email VARCHAR(254) NOT NULL,
    linked_at DATETIME(6) NOT NULL,
    last_authenticated_at DATETIME(6) NULL,
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),

    CONSTRAINT pk_external_identities PRIMARY KEY (id),
    CONSTRAINT uk_external_identity_provider_subject UNIQUE (provider, provider_subject),
    CONSTRAINT fk_external_identities_user
        FOREIGN KEY (user_id) REFERENCES users (id),
    CONSTRAINT ck_external_identity_provider CHECK (provider IN ('GOOGLE'))
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4
  COLLATE = utf8mb4_0900_ai_ci;

CREATE INDEX ix_external_identities_user
    ON external_identities (user_id);
