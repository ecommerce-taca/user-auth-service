package com.ecommerce.authuser.auth.application.signin;

import com.ecommerce.authuser.auth.application.support.IdentityNormalizer;
import com.ecommerce.authuser.auth.exception.signin.AccountLockedException;
import com.ecommerce.authuser.auth.exception.signin.AccountSuspendedException;
import com.ecommerce.authuser.auth.exception.signin.AdminMfaRequiredException;
import com.ecommerce.authuser.auth.exception.signin.InvalidCredentialsException;
import com.ecommerce.authuser.auth.security.AccessTokenService;
import com.ecommerce.authuser.auth.security.PasswordHasher;
import com.ecommerce.authuser.auth.security.PasswordTimingProtector;
import com.ecommerce.authuser.auth.security.SecureTokenGenerator;
import com.ecommerce.authuser.auth.security.TokenHasher;
import com.ecommerce.authuser.common.id.UuidV7Generator;
import com.ecommerce.authuser.mfa.domain.MfaChallenge;
import com.ecommerce.authuser.mfa.domain.MfaPurpose;
import com.ecommerce.authuser.mfa.domain.TwoFactorCredential;
import com.ecommerce.authuser.mfa.domain.TwoFactorStatus;
import com.ecommerce.authuser.mfa.repository.MfaChallengeRepository;
import com.ecommerce.authuser.mfa.repository.TwoFactorCredentialRepository;
import com.ecommerce.authuser.rbac.domain.UserRole;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;
import com.ecommerce.authuser.security.domain.LoginAttempt;
import com.ecommerce.authuser.security.repository.LoginAttemptRepository;
import com.ecommerce.authuser.security.service.AuditValueHasher;
import com.ecommerce.authuser.token.domain.RefreshToken;
import com.ecommerce.authuser.token.repository.RefreshTokenRepository;
import com.ecommerce.authuser.user.domain.User;
import com.ecommerce.authuser.user.domain.UserStatus;
import com.ecommerce.authuser.user.repository.UserRepository;

import static com.ecommerce.authuser.auth.application.support.AuthTokenPolicy.ACCESS_TOKEN_TTL;
import static com.ecommerce.authuser.auth.application.support.AuthTokenPolicy.REFRESH_TOKEN_TTL;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SigninService {

    private static final Duration MFA_LOGIN_CHALLENGE_TTL = Duration.ofMinutes(5);

    private final UserRepository userRepository;

    private final UserRoleRepository userRoleRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final IdentityNormalizer identityNormalizer;

    private final PasswordHasher passwordHasher;

    private final PasswordTimingProtector passwordTimingProtector;

    private final SecureTokenGenerator tokenGenerator;

    private final TokenHasher tokenHasher;

    private final AccessTokenService accessTokenService;

    private final LoginAttemptRepository loginAttemptRepository;

    private final AuditValueHasher auditValueHasher;

    private final TwoFactorCredentialRepository twoFactorCredentialRepository;

    private final MfaChallengeRepository mfaChallengeRepository;

    private static final List<String> ADMIN_ROLES =
            List.of(
                    "SUPER_ADMIN",
                    "RISK_MANAGER",
                    "CATALOG_ADMIN",
                    "FINANCE_OPS",
                    "SUPPORT_VIEWER"
            );

    @Transactional(
            noRollbackFor = {
                    InvalidCredentialsException.class,
                    AccountLockedException.class,
                    AdminMfaRequiredException.class
            }
    )
    public SigninResult signin(SigninCommand command) {

        Instant now = Instant.now();

        String identifier = command.identifier().trim();

        String normalizedAuditIdentifier =
                normalizeIdentifierForAudit(identifier);

        String identifierHash =
                auditValueHasher.hash(normalizedAuditIdentifier);

        String clientIp =
                command.clientIp() == null
                        || command.clientIp().isBlank()
                        ? "unknown"
                        : command.clientIp().trim();

        String ipHash =
                auditValueHasher.hash(
                        clientIp
                );

        String userAgentHash =
                command.userAgent() == null
                        || command.userAgent().isBlank()
                        ? null
                        : auditValueHasher.hash(
                        command.userAgent()
                );

        Optional<User> userOptional = findUserForUpdate(identifier);

        if (userOptional.isEmpty()) {
            passwordTimingProtector.consume(command.password());

            loginAttemptRepository.save(
                    LoginAttempt.failure(
                            null,
                            identifierHash,
                            "INVALID_CREDENTIALS",
                            ipHash,
                            userAgentHash,
                            now
                    )
            );

            throw new InvalidCredentialsException();
        }

        User user = userOptional.get();

        if (user.getStatus() == UserStatus.SUSPENDED
                || user.getStatus() == UserStatus.DELETED) {

            throw new AccountSuspendedException();
        }

        if (user.getStatus() == UserStatus.LOCKED) {

            if (user.isLoginLocked(now)) {
                loginAttemptRepository.save(
                        LoginAttempt.failure(
                                user,
                                identifierHash,
                                "ACCOUNT_LOCKED",
                                ipHash,
                                userAgentHash,
                                now
                        )
                );

                throw new AccountLockedException(
                        user.getLockedUntil()
                );
            }

            if (user.canUnlock(now)) {
                user.unlock(now);
            }
        }

        boolean passwordMatches = user.getPasswordHash() != null
                && passwordHasher.matches(
                        command.password(),
                        user.getPasswordHash()
                );

        if (!passwordMatches) {
            user.recordLoginFailure(now);

            loginAttemptRepository.save(
                    LoginAttempt.failure(
                            user,
                            identifierHash,
                            "INVALID_CREDENTIALS",
                            ipHash,
                            userAgentHash,
                            now
                    )
            );

            if (user.isLoginLocked(now)) {
                throw new AccountLockedException(
                        user.getLockedUntil()
                );
            }

            throw new InvalidCredentialsException();
        }

        user.recordLoginSuccess();

        List<String> roles = loadRoles(user.getId());

        boolean adminUser = roles.stream().anyMatch(ADMIN_ROLES::contains);

        TwoFactorStatus mfaStatus = null;

        if (adminUser) {

            mfaStatus =
                    twoFactorCredentialRepository
                            .findByUserIdForUpdate(
                                    user.getId()
                            )
                            .map(TwoFactorCredential::getStatus)
                            .orElse(null);
        }

        List<String> mfaMethods;

        if (mfaStatus == TwoFactorStatus.ENABLED) {
            mfaMethods = List.of("TOTP", "RECOVERY_CODE");
        } else if (mfaStatus == TwoFactorStatus.RESET_REQUIRED) {
            mfaMethods = List.of("RECOVERY_CODE");
        } else {
            mfaMethods = List.of();
        }

        if (adminUser
                && !mfaMethods.isEmpty()) {
            List<MfaChallenge> activeChallenges =
                    mfaChallengeRepository
                            .findActiveForUpdate(
                                    user.getId(),
                                    MfaPurpose.LOGIN,
                                    now
                            );

            activeChallenges.forEach(challenge -> challenge.revoke(now));

            Instant challengeExpiresAt = now.plus(MFA_LOGIN_CHALLENGE_TTL);

            MfaChallenge challenge = MfaChallenge.create(
                            user,
                            MfaPurpose.LOGIN,
                            null,
                            now,
                            challengeExpiresAt
                    );

            challenge.attachLoginAuditContext(
                    identifierHash,
                    ipHash,
                    userAgentHash
            );

            mfaChallengeRepository.save(challenge);

            throw new AdminMfaRequiredException(
                    challenge.getId(),
                    challengeExpiresAt,
                    mfaMethods
            );
        }

        String rawRefreshToken = tokenGenerator.generate();

        String refreshTokenHash = tokenHasher.hash(rawRefreshToken);

        UUID familyId = UuidV7Generator.generate();

        RefreshToken refreshToken = RefreshToken.issue(
                user,
                refreshTokenHash,
                familyId,
                now,
                now.plus(REFRESH_TOKEN_TTL)
        );

        refreshTokenRepository.save(refreshToken);

        boolean emailVerified = user.getEmailVerifiedAt() != null;

        boolean phoneVerified = user.getPhoneVerifiedAt() != null;

        String accessToken = accessTokenService.issue(
                user.getId(),
                familyId,
                roles,
                emailVerified,
                now,
                now.plus(ACCESS_TOKEN_TTL)
        );

        loginAttemptRepository.save(
                LoginAttempt.success(
                        user,
                        identifierHash,
                        ipHash,
                        userAgentHash,
                        now
                )
        );

        return new SigninResult(
                user.getId(),
                user.getFullName(),
                user.getEmail(),
                emailVerified,
                user.getPhone(),
                phoneVerified,
                roles,
                user.getStatus().name(),
                accessToken,
                rawRefreshToken,
                ACCESS_TOKEN_TTL.toSeconds(),
                REFRESH_TOKEN_TTL.toSeconds()
        );
    }

    private Optional<User> findUserForUpdate(String identifier) {
        try {

            if (identifier.contains("@")) {
                String emailNormalized = identityNormalizer
                        .normalizeEmail(identifier);

                return userRepository.findByEmailNormalizedForUpdate(
                        emailNormalized
                );
            }

            String phoneNormalized = identityNormalizer
                    .normalizePhone(identifier);

            if (phoneNormalized == null) {
                return Optional.empty();
            }

            return userRepository.findByPhoneNormalizedForUpdate(phoneNormalized);

        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private List<String> loadRoles(UUID userId) {
        return userRoleRepository
                .findAllByUser_IdAndRevokedAtIsNull(userId)
                .stream()
                .map(UserRole::getRole)
                .map(role -> role.getRoleKey())
                .distinct()
                .sorted()
                .toList();
    }

    private String normalizeIdentifierForAudit(String identifier) {
        try {
            if (identifier.contains("@")) {
                return identityNormalizer
                        .normalizeEmail(identifier);
            }

            String phone = identityNormalizer.normalizePhone(identifier);

            if (phone != null) {
                return phone;
            }

        } catch (IllegalArgumentException ignored) {
            // fallback below
        }

        return identifier
                .trim()
                .toLowerCase(Locale.ROOT);
    }
}
