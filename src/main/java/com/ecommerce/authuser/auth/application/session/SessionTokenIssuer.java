package com.ecommerce.authuser.auth.application.session;

import com.ecommerce.authuser.auth.security.AccessTokenService;
import com.ecommerce.authuser.auth.security.SecureTokenGenerator;
import com.ecommerce.authuser.auth.security.TokenHasher;
import com.ecommerce.authuser.common.id.UuidV7Generator;
import com.ecommerce.authuser.rbac.domain.UserRole;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;
import com.ecommerce.authuser.token.domain.RefreshToken;
import com.ecommerce.authuser.token.repository.RefreshTokenRepository;
import com.ecommerce.authuser.user.domain.User;

import static com.ecommerce.authuser.auth.application.support.AuthTokenPolicy.ACCESS_TOKEN_TTL;
import static com.ecommerce.authuser.auth.application.support.AuthTokenPolicy.REFRESH_TOKEN_TTL;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SessionTokenIssuer {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRoleRepository userRoleRepository;
    private final SecureTokenGenerator tokenGenerator;
    private final TokenHasher tokenHasher;
    private final AccessTokenService accessTokenService;

    public SessionTokenPair issue(User user, Instant now) {
        List<String> roles = userRoleRepository
                .findAllByUser_IdAndRevokedAtIsNull(user.getId())
                .stream()
                .map(UserRole::getRole)
                .map(role -> role.getRoleKey())
                .distinct()
                .sorted()
                .toList();
        String rawRefreshToken = tokenGenerator.generate();
        UUID sessionId = UuidV7Generator.generate();

        refreshTokenRepository.save(
                RefreshToken.issue(
                        user,
                        tokenHasher.hash(rawRefreshToken),
                        sessionId,
                        now,
                        now.plus(REFRESH_TOKEN_TTL)
                )
        );

        String accessToken = accessTokenService.issue(
                user.getId(),
                sessionId,
                roles,
                user.getEmailVerifiedAt() != null,
                now,
                now.plus(ACCESS_TOKEN_TTL)
        );

        return new SessionTokenPair(
                accessToken,
                rawRefreshToken,
                ACCESS_TOKEN_TTL.toSeconds(),
                REFRESH_TOKEN_TTL.toSeconds()
        );
    }
}
