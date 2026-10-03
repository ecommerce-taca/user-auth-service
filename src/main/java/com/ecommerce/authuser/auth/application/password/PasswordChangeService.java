package com.ecommerce.authuser.auth.application.password;

import com.ecommerce.authuser.audit.domain.AuditLog;
import com.ecommerce.authuser.audit.domain.AuditTargetType;
import com.ecommerce.authuser.audit.repository.AuditLogRepository;
import com.ecommerce.authuser.auth.application.session.SessionTokenIssuer;
import com.ecommerce.authuser.auth.application.session.SessionTokenPair;
import com.ecommerce.authuser.auth.exception.mfa.MfaStepUpRequiredException;
import com.ecommerce.authuser.auth.exception.password.InvalidCurrentPasswordException;
import com.ecommerce.authuser.auth.exception.password.InvalidPasswordInputException;
import com.ecommerce.authuser.auth.exception.password.PasswordReuseException;
import com.ecommerce.authuser.auth.security.PasswordHasher;
import com.ecommerce.authuser.mfa.application.admin.AdminStepUpService;
import com.ecommerce.authuser.mfa.repository.MfaStepUpTokenRepository;
import com.ecommerce.authuser.outbox.domain.OutboxAggregateType;
import com.ecommerce.authuser.outbox.domain.OutboxEvent;
import com.ecommerce.authuser.outbox.repository.OutboxEventRepository;
import com.ecommerce.authuser.outbox.security.OutboxPayloadProtector;
import com.ecommerce.authuser.security.service.AuditValueHasher;
import com.ecommerce.authuser.token.domain.RefreshToken;
import com.ecommerce.authuser.token.domain.TokenRevokeReason;
import com.ecommerce.authuser.token.repository.RefreshTokenRepository;
import com.ecommerce.authuser.user.domain.User;
import com.ecommerce.authuser.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordChangeService {

    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final int MAX_PASSWORD_LENGTH = 72;

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final MfaStepUpTokenRepository mfaStepUpTokenRepository;
    private final PasswordHasher passwordHasher;
    private final AdminStepUpService adminStepUpService;
    private final SessionTokenIssuer sessionTokenIssuer;
    private final AuditLogRepository auditLogRepository;
    private final AuditValueHasher auditValueHasher;
    private final OutboxEventRepository outboxEventRepository;
    private final OutboxPayloadProtector outboxPayloadProtector;

    @Transactional(noRollbackFor = MfaStepUpRequiredException.class)
    public PasswordChangeResult change(PasswordChangeCommand command) {
        validateCommand(command);

        Instant now = Instant.now();
        User user = userRepository
                .findByIdForUpdate(command.userId())
                .orElseThrow(InvalidCurrentPasswordException::new);

        if (!passwordHasher.matches(command.currentPassword(), user.getPasswordHash())) {
            throw new InvalidCurrentPasswordException();
        }

        if (passwordHasher.matches(command.newPassword(), user.getPasswordHash())) {
            throw new PasswordReuseException();
        }

        if (command.allSessions()) {
            adminStepUpService.require(
                    user.getId(),
                    command.sessionId(),
                    command.stepUpToken(),
                    now
            );
        }

        user.changePassword(passwordHasher.hash(command.newPassword()), now);

        long revokedSessionCount = revokeSessions(user.getId(), command.sessionId(), command.allSessions(), now);
        SessionTokenPair sessionTokens = command.allSessions()
                ? sessionTokenIssuer.issue(user, now)
                : null;

        if (command.allSessions()) {
            revokeStepUpTokens(user.getId(), now);
        }

        outboxEventRepository.save(OutboxEvent.create(
                OutboxAggregateType.USER,
                user.getId(),
                "user.password_changed",
                (short) 1,
                user.getId().toString(),
                outboxPayloadProtector.protect(
                        "user.password_changed",
                        Map.of(
                                "user_id", user.getId().toString(),
                                "password_changed_at", now.toString()
                        )
                )
        ));

        saveAudit(command, revokedSessionCount, now);

        return new PasswordChangeResult(
                command.allSessions(),
                revokedSessionCount,
                sessionTokens
        );
    }

    private long revokeSessions(UUID userId, UUID currentSessionId, boolean allSessions, Instant now) {
        List<RefreshToken> activeTokens = refreshTokenRepository.findAllActiveByUserForUpdate(userId);

        return activeTokens.stream()
                .filter(token -> allSessions || !token.getFamilyId().equals(currentSessionId))
                .peek(token -> token.revoke(TokenRevokeReason.PASSWORD_CHANGE, now))
                .count();
    }

    private void revokeStepUpTokens(UUID userId, Instant now) {
        mfaStepUpTokenRepository.findAllActiveByUserForUpdate(userId)
                .forEach(token -> token.revoke(now));
    }

    private void saveAudit(PasswordChangeCommand command, long revokedSessionCount, Instant now) {
        String clientIp = command.clientIp() == null || command.clientIp().isBlank()
                ? "unknown"
                : command.clientIp().trim();

        auditLogRepository.save(AuditLog.create(
                command.userId(),
                "AUTH_PASSWORD_CHANGED",
                AuditTargetType.USER,
                command.userId(),
                "User changed password",
                Map.of(
                        "session_id", command.sessionId().toString(),
                        "all_sessions", command.allSessions(),
                        "sessions_revoked", revokedSessionCount
                ),
                auditValueHasher.hash(clientIp),
                now
        ));
    }

    private void validateCommand(PasswordChangeCommand command) {
        if (command == null || command.userId() == null || command.sessionId() == null) {
            throw new InvalidCurrentPasswordException();
        }

        if (command.currentPassword() == null
                || command.currentPassword().isBlank()
                || command.currentPassword().length() > MAX_PASSWORD_LENGTH) {
            throw new InvalidCurrentPasswordException();
        }

        if (command.newPassword() == null
                || command.newPassword().length() < MIN_PASSWORD_LENGTH
                || command.newPassword().length() > MAX_PASSWORD_LENGTH) {
            throw new InvalidPasswordInputException();
        }
    }
}
