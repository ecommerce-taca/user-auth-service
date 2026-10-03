package com.ecommerce.authuser.auth.application.password;

import com.ecommerce.authuser.auth.exception.password.InvalidPasswordInputException;
import com.ecommerce.authuser.auth.exception.password.InvalidPasswordResetTokenException;
import com.ecommerce.authuser.auth.application.session.SessionTokenIssuer;
import com.ecommerce.authuser.auth.application.session.SessionTokenPair;
import com.ecommerce.authuser.auth.security.PasswordHasher;
import com.ecommerce.authuser.auth.security.TokenHasher;

import com.ecommerce.authuser.outbox.domain.OutboxAggregateType;
import com.ecommerce.authuser.outbox.domain.OutboxEvent;
import com.ecommerce.authuser.outbox.repository.OutboxEventRepository;
import com.ecommerce.authuser.outbox.security.OutboxPayloadProtector;

import com.ecommerce.authuser.token.domain.PasswordResetToken;
import com.ecommerce.authuser.token.domain.RefreshToken;
import com.ecommerce.authuser.token.domain.TokenRevokeReason;

import com.ecommerce.authuser.token.repository.PasswordResetTokenLookup;
import com.ecommerce.authuser.token.repository.PasswordResetTokenRepository;
import com.ecommerce.authuser.token.repository.RefreshTokenRepository;

import com.ecommerce.authuser.user.domain.User;
import com.ecommerce.authuser.user.domain.UserStatus;
import com.ecommerce.authuser.user.repository.UserRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private static final int MIN_PASSWORD_LENGTH = 12;

    private static final int MAX_PASSWORD_LENGTH = 72;

    private final PasswordResetTokenRepository passwordResetTokenRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final UserRepository userRepository;

    private final TokenHasher tokenHasher;

    private final PasswordHasher passwordHasher;

    private final SessionTokenIssuer sessionTokenIssuer;

    private final OutboxEventRepository outboxEventRepository;

    private final OutboxPayloadProtector outboxPayloadProtector;

    @Transactional
    public PasswordResetResult reset(PasswordResetCommand command) {
        validateCommand(command);

        Instant now = Instant.now();

        String tokenHash = tokenHasher.hash(command.token());

        PasswordResetTokenLookup lookup = passwordResetTokenRepository
                .findLookupByTokenHash(tokenHash)
                .orElseThrow(InvalidPasswordResetTokenException::new);

        User user = userRepository
                .findByIdForUpdate(lookup.userId())
                .orElseThrow(InvalidPasswordResetTokenException::new);

        if (user.getStatus() == UserStatus.SUSPENDED
                || user.getStatus() == UserStatus.DELETED) {
            throw new InvalidPasswordResetTokenException();
        }

        PasswordResetToken resetToken = passwordResetTokenRepository
                .findByIdForUpdate(lookup.tokenId())
                .orElseThrow(InvalidPasswordResetTokenException::new);

        if (!resetToken
                .getUser()
                .getId()
                .equals(user.getId())) {

            throw new InvalidPasswordResetTokenException();
        }

        if (!resetToken.isUsable(now)) {
            throw new InvalidPasswordResetTokenException();
        }

        String newPasswordHash = passwordHasher.hash(command.newPassword());

        user.changePassword(newPasswordHash, now);

        resetToken.markUsed(now);

        List<RefreshToken> activeRefreshTokens = refreshTokenRepository
                .findAllActiveByUserForUpdate(user.getId());

        activeRefreshTokens.forEach(
                token ->
                        token.revoke(TokenRevokeReason.RESET, now)
        );

        SessionTokenPair sessionTokens = sessionTokenIssuer.issue(user, now);

        OutboxEvent passwordChangedEvent =
                OutboxEvent.create(
                        OutboxAggregateType.USER,

                        user.getId(),

                        "user.password_changed",

                        (short) 1,

                        user.getId()
                                .toString(),

                        outboxPayloadProtector.protect(
                                "user.password_changed",

                                Map.of(
                                        "user_id",
                                        user.getId()
                                                .toString(),

                                        "password_changed_at",
                                        now.toString()
                                )
                        )
                );

        outboxEventRepository.save(passwordChangedEvent);

        return new PasswordResetResult(
                sessionTokens.accessToken(),
                sessionTokens.refreshToken(),
                sessionTokens.accessExpiresIn(),
                sessionTokens.refreshExpiresIn()
        );
    }

    private void validateCommand(
            PasswordResetCommand command
    ) {

        if (command == null
                || command.token() == null
                || command.token().isBlank()
                || command.token().length() > 512) {

            throw new InvalidPasswordResetTokenException();
        }

        String newPassword = command.newPassword();

        if (newPassword == null
                || newPassword.length() < MIN_PASSWORD_LENGTH
                || newPassword.length() > MAX_PASSWORD_LENGTH) {

            throw new InvalidPasswordInputException();
        }
    }
}
