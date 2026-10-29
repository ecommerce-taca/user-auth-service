package com.ecommerce.authuser.auth.application.google;

import com.ecommerce.authuser.auth.application.session.SessionTokenIssuer;
import com.ecommerce.authuser.auth.application.session.SessionTokenPair;
import com.ecommerce.authuser.auth.application.support.IdentityNormalizer;
import com.ecommerce.authuser.auth.exception.signin.AccountLockedException;
import com.ecommerce.authuser.auth.exception.signin.AccountSuspendedException;
import com.ecommerce.authuser.auth.exception.signin.AdminMfaRequiredException;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentity;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityProvider;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityRepository;
import com.ecommerce.authuser.auth.google.GoogleIdTokenVerifier;
import com.ecommerce.authuser.auth.google.GoogleIdentity;
import com.ecommerce.authuser.mfa.domain.MfaChallenge;
import com.ecommerce.authuser.mfa.domain.MfaPurpose;
import com.ecommerce.authuser.mfa.domain.TwoFactorCredential;
import com.ecommerce.authuser.mfa.domain.TwoFactorStatus;
import com.ecommerce.authuser.mfa.repository.MfaChallengeRepository;
import com.ecommerce.authuser.mfa.repository.TwoFactorCredentialRepository;
import com.ecommerce.authuser.outbox.domain.OutboxAggregateType;
import com.ecommerce.authuser.outbox.domain.OutboxEvent;
import com.ecommerce.authuser.outbox.repository.OutboxEventRepository;
import com.ecommerce.authuser.outbox.security.OutboxPayloadProtector;
import com.ecommerce.authuser.rbac.domain.Role;
import com.ecommerce.authuser.rbac.domain.UserRole;
import com.ecommerce.authuser.rbac.repository.RoleRepository;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;
import com.ecommerce.authuser.security.domain.LoginAttempt;
import com.ecommerce.authuser.security.repository.LoginAttemptRepository;
import com.ecommerce.authuser.security.service.AuditValueHasher;
import com.ecommerce.authuser.user.domain.User;
import com.ecommerce.authuser.user.domain.UserStatus;
import com.ecommerce.authuser.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class GoogleSigninService {

    private static final Duration MFA_LOGIN_CHALLENGE_TTL = Duration.ofMinutes(5);
    private static final List<String> ADMIN_ROLES = List.of(
            "SUPER_ADMIN", "RISK_MANAGER", "CATALOG_ADMIN", "FINANCE_OPS", "SUPPORT_VIEWER");

    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final ExternalIdentityRepository externalIdentityRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final SessionTokenIssuer sessionTokenIssuer;
    private final LoginAttemptRepository loginAttemptRepository;
    private final AuditValueHasher auditValueHasher;
    private final TwoFactorCredentialRepository twoFactorCredentialRepository;
    private final MfaChallengeRepository mfaChallengeRepository;
    private final IdentityNormalizer identityNormalizer;
    private final OutboxEventRepository outboxEventRepository;
    private final OutboxPayloadProtector outboxPayloadProtector;

    @Transactional(noRollbackFor = {AccountLockedException.class, AdminMfaRequiredException.class})
    public GoogleSigninResult signin(GoogleSigninCommand command) {
        GoogleIdentity googleIdentity = googleIdTokenVerifier.verify(command.idToken());
        Instant now = Instant.now();
        String identifierHash = auditValueHasher.hash("google:" + googleIdentity.subject());
        String ipHash = auditValueHasher.hash(clientIp(command.clientIp()));
        String userAgentHash = userAgentHash(command.userAgent());

        ExternalIdentity identity = externalIdentityRepository
                .findByProviderAndProviderSubject(ExternalIdentityProvider.GOOGLE, googleIdentity.subject())
                .orElse(null);

        boolean created = false;
        User user;
        if (identity == null) {
            String email = googleIdentity.email().trim();
            String normalizedEmail;
            try {
                normalizedEmail = identityNormalizer.normalizeEmail(email);
            } catch (IllegalArgumentException ex) {
                throw new com.ecommerce.authuser.auth.google.InvalidGoogleIdTokenException(ex);
            }

            if (userRepository.findByEmailNormalizedForUpdate(normalizedEmail).isPresent()) {
                throw new GoogleAccountLinkRequiredException();
            }

            user = User.registerBuyer(
                    email,
                    normalizedEmail,
                    null,
                    resolvedFullName(googleIdentity.fullName(), email),
                    null,
                    null);
            user.verifyEmail(now);
            userRepository.save(user);
            assignBuyerRole(user);
            externalIdentityRepository.save(ExternalIdentity.linkGoogle(
                    user, googleIdentity.subject(), email, now));
            publishUserCreated(user);
            created = true;
        } else {
            user = identity.getUser();
            identity.recordAuthentication(googleIdentity.email().trim(), now);
        }

        assertAccountCanSignIn(user, now, identifierHash, ipHash, userAgentHash);
        user.recordLoginSuccess();

        List<String> roles = loadRoles(user);
        requireMfaIfNeeded(user, roles, now, identifierHash, ipHash, userAgentHash);
        SessionTokenPair tokens = sessionTokenIssuer.issue(user, now);

        loginAttemptRepository.save(LoginAttempt.success(
                user, identifierHash, ipHash, userAgentHash, now));

        return new GoogleSigninResult(
                user.getId(), user.getFullName(), user.getEmail(), true,
                user.getPhone(), user.getPhoneVerifiedAt() != null, roles, user.getStatus().name(), created,
                tokens.accessToken(), tokens.accessExpiresIn(), tokens.refreshToken(), tokens.refreshExpiresIn());
    }

    private void assertAccountCanSignIn(User user, Instant now, String identifierHash, String ipHash,
            String userAgentHash) {
        if (user.getStatus() == UserStatus.SUSPENDED || user.getStatus() == UserStatus.DELETED) {
            throw new AccountSuspendedException();
        }
        if (user.getStatus() != UserStatus.LOCKED) {
            return;
        }
        if (user.isLoginLocked(now)) {
            loginAttemptRepository.save(LoginAttempt.failure(
                    user, identifierHash, "ACCOUNT_LOCKED", ipHash, userAgentHash, now));
            throw new AccountLockedException(user.getLockedUntil());
        }
        if (user.canUnlock(now)) {
            user.unlock(now);
        }
    }

    private void requireMfaIfNeeded(User user, List<String> roles, Instant now, String identifierHash,
            String ipHash, String userAgentHash) {
        if (roles.stream().noneMatch(ADMIN_ROLES::contains)) {
            return;
        }
        TwoFactorStatus mfaStatus = twoFactorCredentialRepository.findByUserIdForUpdate(user.getId())
                .map(TwoFactorCredential::getStatus).orElse(null);
        List<String> methods = mfaStatus == TwoFactorStatus.ENABLED
                ? List.of("TOTP", "RECOVERY_CODE")
                : mfaStatus == TwoFactorStatus.RESET_REQUIRED ? List.of("RECOVERY_CODE") : List.of();
        if (methods.isEmpty()) {
            return;
        }
        mfaChallengeRepository.findActiveForUpdate(user.getId(), MfaPurpose.LOGIN, now)
                .forEach(challenge -> challenge.revoke(now));
        Instant expiresAt = now.plus(MFA_LOGIN_CHALLENGE_TTL);
        MfaChallenge challenge = MfaChallenge.create(user, MfaPurpose.LOGIN, null, now, expiresAt);
        challenge.attachLoginAuditContext(identifierHash, ipHash, userAgentHash);
        mfaChallengeRepository.save(challenge);
        throw new AdminMfaRequiredException(challenge.getId(), expiresAt, methods);
    }

    private void assignBuyerRole(User user) {
        Role buyerRole = roleRepository.findByRoleKey("BUYER")
                .orElseThrow(() -> new IllegalStateException("BUYER role is missing"));
        userRoleRepository.save(UserRole.assign(user, buyerRole, null, null));
    }

    private void publishUserCreated(User user) {
        outboxEventRepository.save(OutboxEvent.create(
                OutboxAggregateType.USER, user.getId(), "user.created", (short) 1, user.getId().toString(),
                outboxPayloadProtector.protect("user.created", Map.of(
                        "user_id", user.getId().toString(), "email", user.getEmail(),
                        "status", "ACTIVE", "roles", List.of("BUYER")))));
    }

    private List<String> loadRoles(User user) {
        return userRoleRepository.findAllByUser_IdAndRevokedAtIsNull(user.getId()).stream()
                .map(UserRole::getRole).map(Role::getRoleKey).distinct().sorted().toList();
    }

    private String clientIp(String value) {
        return value == null || value.isBlank() ? "unknown" : value.trim();
    }

    private String userAgentHash(String userAgent) {
        return userAgent == null || userAgent.isBlank() ? null : auditValueHasher.hash(userAgent);
    }

    private String resolvedFullName(String fullName, String email) {
        if (fullName != null && !fullName.isBlank()) {
            return fullName.trim().substring(0, Math.min(fullName.trim().length(), 120));
        }
        return email.substring(0, Math.min(email.length(), 120));
    }
}
