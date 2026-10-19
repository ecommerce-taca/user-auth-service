package com.ecommerce.authuser.auth.security;

import com.ecommerce.authuser.auth.config.JwtKeyProperties;
import com.ecommerce.authuser.common.id.UuidV7Generator;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import lombok.RequiredArgsConstructor;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtAccessTokenService implements AccessTokenService {

    private static final String ISSUER = "auth-user-service";

    private static final String AUDIENCE = "taca-api";

    private static final String SELLER_ROLE = "SELLER";

    private final JwtEncoder jwtEncoder;

    private final JwtKeyProperties jwtKeyProperties;

    private final ShopRepository shopRepository;

    @Override
    public String issue(
            UUID userId,
            UUID sessionId,
            List<String> roles,
            boolean emailVerified,
            Instant issuedAt,
            Instant expiresAt
    ) {
        Objects.requireNonNull(userId);
        Objects.requireNonNull(sessionId);
        Objects.requireNonNull(roles);
        Objects.requireNonNull(issuedAt);
        Objects.requireNonNull(expiresAt);

        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException(
                    "expiresAt must be after issuedAt"
            );
        }

        JwtClaimsSet.Builder builder =
                JwtClaimsSet.builder()
                        .issuer(ISSUER)
                        .audience(List.of(AUDIENCE))
                        .subject(userId.toString())
                        .issuedAt(issuedAt)
                        .expiresAt(expiresAt)
                        .id(UuidV7Generator.generate().toString())
                        .claim("session_id", sessionId.toString())
                        .claim("roles", List.copyOf(roles))
                        .claim("email_verified", emailVerified);

        // Shop scope cho Gateway (api-gateway LLD §2.4): Kong chuyển claim shop_id thành X-User-Shop-Scope,
        // Product Catalog dựa vào header này để biết seller thao tác trên shop nào.
        if (roles.contains(SELLER_ROLE)) {
            shopRepository
                    .findFirstByOwner_IdAndDeletedAtIsNullOrderByCreatedAtDesc(userId)
                    .ifPresent(shop -> builder.claim("shop_id", shop.getId().toString()));
        }

        JwtClaimsSet claims = builder.build();

        JwsHeader headers = JwsHeader
                .with(SignatureAlgorithm.RS256)
                .keyId(jwtKeyProperties.keyId())
                .build();

        return jwtEncoder
                .encode(JwtEncoderParameters.from(headers, claims))
                .getTokenValue();
    }
}
