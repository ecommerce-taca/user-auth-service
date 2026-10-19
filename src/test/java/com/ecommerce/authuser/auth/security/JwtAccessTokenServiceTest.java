package com.ecommerce.authuser.auth.security;

import com.ecommerce.authuser.auth.config.JwtKeyProperties;
import com.ecommerce.authuser.shop.domain.Shop;
import com.ecommerce.authuser.shop.repository.ShopRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class JwtAccessTokenServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-19T10:00:00Z");

    private final JwtEncoder jwtEncoder = mock(JwtEncoder.class);

    private final ShopRepository shopRepository = mock(ShopRepository.class);

    private final ArgumentCaptor<JwtEncoderParameters> parameters =
            ArgumentCaptor.forClass(JwtEncoderParameters.class);

    private JwtAccessTokenService service;

    @BeforeEach
    void setUp() {
        service = new JwtAccessTokenService(
                jwtEncoder,
                new JwtKeyProperties("kid-test", "priv", "pub", null, null),
                shopRepository
        );
        when(jwtEncoder.encode(parameters.capture())).thenReturn(
                new Jwt("token", NOW, NOW.plusSeconds(900), Map.of("alg", "RS256"), Map.of("sub", "x"))
        );
    }

    @Test
    void sellerWithShopGetsShopIdClaim() {
        UUID userId = UUID.randomUUID();
        UUID shopId = UUID.randomUUID();
        Shop shop = mock(Shop.class);
        when(shop.getId()).thenReturn(shopId);
        when(shopRepository.findFirstByOwner_IdAndDeletedAtIsNullOrderByCreatedAtDesc(userId))
                .thenReturn(Optional.of(shop));

        service.issue(userId, UUID.randomUUID(), List.of("BUYER", "SELLER"), true, NOW, NOW.plusSeconds(900));

        assertThat(parameters.getValue().getClaims().getClaims())
                .containsEntry("shop_id", shopId.toString());
    }

    @Test
    void sellerWithoutShopHasNoShopIdClaim() {
        UUID userId = UUID.randomUUID();
        when(shopRepository.findFirstByOwner_IdAndDeletedAtIsNullOrderByCreatedAtDesc(any()))
                .thenReturn(Optional.empty());

        service.issue(userId, UUID.randomUUID(), List.of("SELLER"), true, NOW, NOW.plusSeconds(900));

        assertThat(parameters.getValue().getClaims().getClaims()).doesNotContainKey("shop_id");
    }

    @Test
    void buyerDoesNotQueryShops() {
        service.issue(UUID.randomUUID(), UUID.randomUUID(), List.of("BUYER"), true, NOW, NOW.plusSeconds(900));

        assertThat(parameters.getValue().getClaims().getClaims()).doesNotContainKey("shop_id");
        verifyNoInteractions(shopRepository);
    }
}
