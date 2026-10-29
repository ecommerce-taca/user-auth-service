package com.ecommerce.authuser.auth.google;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class NimbusGoogleIdTokenVerifier implements GoogleIdTokenVerifier {

    private static final List<String> GOOGLE_ISSUERS = List.of(
            "https://accounts.google.com", "accounts.google.com");

    private final List<String> allowedClientIds;

    private final NimbusJwtDecoder decoder;

    public NimbusGoogleIdTokenVerifier(GoogleIdTokenProperties properties) {
        allowedClientIds = properties.resolvedAllowedClientIds();
        decoder = buildDecoder(properties.resolvedJwkSetUri(), allowedClientIds);
    }

    @Override
    public GoogleIdentity verify(String idToken) {
        if (idToken == null || idToken.isBlank()) {
            throw new InvalidGoogleIdTokenException();
        }

        if (allowedClientIds.isEmpty()) {
            throw new GoogleSigninUnavailableException();
        }

        try {
            Jwt jwt = decoder.decode(idToken);
            String subject = jwt.getSubject();
            String email = jwt.getClaimAsString("email");
            Boolean emailVerified = jwt.getClaim("email_verified");

            if (subject == null || subject.isBlank() || subject.length() > 255
                    || email == null || email.isBlank() || email.length() > 254
                    || !Boolean.TRUE.equals(emailVerified)) {
                throw new InvalidGoogleIdTokenException();
            }

            String fullName = jwt.getClaimAsString("name");
            return new GoogleIdentity(subject, email, fullName);
        } catch (JwtException ex) {
            throw new InvalidGoogleIdTokenException(ex);
        }
    }

    private NimbusJwtDecoder buildDecoder(String jwkSetUri, List<String> allowedClientIds) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(jwkSetUri)
                .build();

        OAuth2TokenValidator<Jwt> issuerValidator = jwt -> {
            String issuer = jwt.getIssuer() == null ? null : jwt.getIssuer().toString();
            if (GOOGLE_ISSUERS.contains(issuer)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "Google token issuer is invalid", null));
        };

        OAuth2TokenValidator<Jwt> audienceValidator = jwt -> {
            if (jwt.getAudience().stream().anyMatch(allowedClientIds::contains)) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                    "invalid_token", "Google token audience is not allowed", null));
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(),
                issuerValidator,
                audienceValidator));
        return decoder;
    }
}
