package com.ecommerce.authuser.user.domain;

import com.ecommerce.authuser.common.id.UuidV7Generator;
import jakarta.persistence.*;
import lombok.Getter;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Objects;
import java.util.UUID;

@Entity
@Table(name = "users")
@Getter
public class User {
    private static final int MAX_LOGIN_FAILURES = 5;

    private static final Duration LOGIN_FAILURE_WINDOW = Duration.ofMinutes(15);

    private static final Duration LOGIN_LOCK_DURATION = Duration.ofMinutes(15);

    @Id
    @Column(
            name = "id",
            nullable = false,
            updatable = false,
            columnDefinition = "BINARY(16)"
    )
    private UUID id;

    @Column(name = "email", nullable = false, length = 254)
    private String email;

    @Column(name = "email_normalized", nullable = false, length = 254)
    private String emailNormalized;

    @Column(name = "email_verified_at")
    private Instant emailVerifiedAt;

    @Column(name = "phone", length = 16)
    private String phone;

    @Column(name = "phone_normalized", length = 16)
    private String phoneNormalized;

    @Column(name = "phone_verified_at")
    private Instant phoneVerifiedAt;

    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    @Column(name = "full_name", nullable = false, length = 120)
    private String fullName;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private UserStatus status;

    @Column(name = "failed_login_count", nullable = false)
    private short failedLoginCount;

    @Column(name = "failed_login_window_started_at")
    private Instant failedLoginWindowStartedAt;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "password_changed_at")
    private Instant passwordChangedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    protected User() {
    }

    public static User create(
            String email,
            String emailNormalized,
            String phone,
            String phoneNormalized,
            String passwordHash,
            String fullName,
            LocalDate dateOfBirth
    ) {

        User user = new User();

        user.id = UuidV7Generator.generate();
        user.email = email;
        user.emailNormalized = emailNormalized;
        user.phone = phone;
        user.phoneNormalized = phoneNormalized;
        user.passwordHash = passwordHash;
        user.fullName = fullName;
        user.dateOfBirth = dateOfBirth;
        user.status = UserStatus.ACTIVE;
        user.failedLoginCount = 0;

        return user;
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

    public boolean canUnlock(Instant now) {
        Objects.requireNonNull(now);

        return status == UserStatus.LOCKED
                && lockedUntil != null
                && !lockedUntil.isAfter(now);
    }

    public void unlock(Instant now) {
        if (!canUnlock(now)) {
            throw new IllegalStateException(
                    "User cannot be unlocked"
            );
        }

        status = UserStatus.ACTIVE;
        lockedUntil = null;
        failedLoginCount = 0;
        failedLoginWindowStartedAt = null;
    }

    public boolean isLoginLocked(Instant now) {
        Objects.requireNonNull(now);

        return status == UserStatus.LOCKED
                && lockedUntil != null
                && lockedUntil.isAfter(now);
    }

    public void recordLoginFailure(Instant now) {
        Objects.requireNonNull(now);

        if (status == UserStatus.SUSPENDED
                || status == UserStatus.DELETED) {

            throw new IllegalStateException(
                    "Inactive user cannot record login failure"
            );
        }

        if (failedLoginWindowStartedAt == null
                || failedLoginWindowStartedAt.plus(LOGIN_FAILURE_WINDOW).isBefore(now)
                || failedLoginWindowStartedAt.plus(LOGIN_FAILURE_WINDOW).equals(now)) {

            failedLoginWindowStartedAt = now;
            failedLoginCount = 1;
        } else {
            failedLoginCount++;
        }

        if (failedLoginCount >= MAX_LOGIN_FAILURES) {

            status = UserStatus.LOCKED;

            lockedUntil = now.plus(LOGIN_LOCK_DURATION);
        }
    }

    public void recordLoginSuccess() {
        failedLoginCount = 0;
        failedLoginWindowStartedAt = null;
        lockedUntil = null;

        if (status == UserStatus.LOCKED) {
            status = UserStatus.ACTIVE;
        }
    }

    public static User registerBuyer(
            String email,
            String emailNormalized,
            String passwordHash,
            String fullName,
            String phone,
            String phoneNormalized
    ) {

        User user = new User();
        user.id = UuidV7Generator.generate();
        user.email = email;
        user.emailNormalized = emailNormalized;
        user.emailVerifiedAt = null;
        user.passwordHash = passwordHash;
        user.fullName = fullName;
        user.phone = phone;
        user.phoneNormalized = phoneNormalized;
        user.phoneVerifiedAt = null;
        user.status = UserStatus.ACTIVE;
        user.failedLoginCount = 0;

        return user;
    }

    public void verifyEmail(Instant now) {
        Objects.requireNonNull(now);

        if (emailVerifiedAt != null) {
            throw new IllegalStateException(
                    "Email is already verified"
            );
        }

        emailVerifiedAt = now;
    }

    public void verifyPhone(
            String phone,
            String phoneNormalized,
            Instant now
    ) {
        Objects.requireNonNull(phone);
        Objects.requireNonNull(phoneNormalized);
        Objects.requireNonNull(now);

        if (phoneVerifiedAt != null
                && Objects.equals(this.phoneNormalized, phoneNormalized)
        ) {
            throw new IllegalStateException(
                    "Phone is already verified"
            );
        }

        this.phone = phone;
        this.phoneNormalized = phoneNormalized;
        this.phoneVerifiedAt = now;
    }

    public void changePassword(
            String newPasswordHash,
            Instant now
    ) {
        Objects.requireNonNull(newPasswordHash);

        Objects.requireNonNull(now);

        if (newPasswordHash.isBlank()) {
            throw new IllegalArgumentException(
                    "Password hash must not be blank"
            );
        }

        this.passwordHash = newPasswordHash;
        this.passwordChangedAt = now;
    }

    public void updateProfile(
            String fullName,
            boolean updatePhone,
            String phone,
            String phoneNormalized,
            boolean updateDateOfBirth,
            LocalDate dateOfBirth
    ) {
        Objects.requireNonNull(fullName);

        if (fullName.isBlank()) {
            throw new IllegalArgumentException(
                    "Full name must not be blank"
            );
        }

        if (updatePhone) {
            boolean phoneNullMismatch =
                    (phone == null) != (phoneNormalized == null);

            if (phoneNullMismatch) {
                throw new IllegalArgumentException(
                        "Phone and normalized phone must be both null or both non-null"
                );
            }
        }

        this.fullName = fullName;

        if (updatePhone
                && !Objects.equals(
                this.phoneNormalized,
                phoneNormalized
        )) {

            this.phone = phone;
            this.phoneNormalized = phoneNormalized;
            this.phoneVerifiedAt = null;
        }

        if (updateDateOfBirth) {
            this.dateOfBirth = dateOfBirth;
        }
    }

    public void suspend() {
        if (status != UserStatus.ACTIVE && status != UserStatus.LOCKED) {
            throw new IllegalStateException(
                    "User cannot be suspended"
            );
        }

        status = UserStatus.SUSPENDED;

        lockedUntil = null;
        failedLoginCount = 0;
        failedLoginWindowStartedAt = null;
    }

    public void restore() {
        if (status != UserStatus.SUSPENDED) {
            throw new IllegalStateException(
                    "User cannot be restored"
            );
        }

        status = UserStatus.ACTIVE;

        lockedUntil = null;
        failedLoginCount = 0;
        failedLoginWindowStartedAt = null;
    }
}
