package com.ecommerce.authuser.auth.externalidentity;

import com.ecommerce.authuser.common.id.UuidV7Generator;
import com.ecommerce.authuser.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.Getter;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "external_identities")
@Getter
public class ExternalIdentity {

    @Id
    @Column(name = "id", nullable = false, updatable = false, columnDefinition = "BINARY(16)")
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 32, updatable = false)
    private ExternalIdentityProvider provider;

    @Column(name = "provider_subject", nullable = false, length = 255, updatable = false)
    private String providerSubject;

    @Column(name = "provider_email", nullable = false, length = 254)
    private String providerEmail;

    @Column(name = "linked_at", nullable = false, updatable = false)
    private Instant linkedAt;

    @Column(name = "last_authenticated_at")
    private Instant lastAuthenticatedAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected ExternalIdentity() {
    }

    public static ExternalIdentity linkGoogle(User user, String subject, String email, Instant now) {
        Objects.requireNonNull(user);
        Objects.requireNonNull(subject);
        Objects.requireNonNull(email);
        Objects.requireNonNull(now);

        if (subject.isBlank() || email.isBlank()) {
            throw new IllegalArgumentException("Google identity values must not be blank");
        }

        ExternalIdentity identity = new ExternalIdentity();
        identity.id = UuidV7Generator.generate();
        identity.user = user;
        identity.provider = ExternalIdentityProvider.GOOGLE;
        identity.providerSubject = subject;
        identity.providerEmail = email;
        identity.linkedAt = now;
        identity.lastAuthenticatedAt = now;
        return identity;
    }

    public void recordAuthentication(String email, Instant now) {
        Objects.requireNonNull(email);
        Objects.requireNonNull(now);
        providerEmail = email;
        lastAuthenticatedAt = now;
    }

    @PrePersist
    private void prePersist() {
        if (updatedAt == null) {
            updatedAt = Instant.now();
        }
    }

    @PreUpdate
    private void preUpdate() {
        updatedAt = Instant.now();
    }
}
