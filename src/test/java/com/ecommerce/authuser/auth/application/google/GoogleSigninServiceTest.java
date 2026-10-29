package com.ecommerce.authuser.auth.application.google;

import com.ecommerce.authuser.auth.application.session.SessionTokenIssuer;
import com.ecommerce.authuser.auth.application.session.SessionTokenPair;
import com.ecommerce.authuser.auth.application.support.IdentityNormalizer;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentity;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityProvider;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityRepository;
import com.ecommerce.authuser.auth.google.GoogleIdTokenVerifier;
import com.ecommerce.authuser.auth.google.GoogleIdentity;
import com.ecommerce.authuser.mfa.repository.MfaChallengeRepository;
import com.ecommerce.authuser.mfa.repository.TwoFactorCredentialRepository;
import com.ecommerce.authuser.outbox.repository.OutboxEventRepository;
import com.ecommerce.authuser.outbox.security.OutboxPayloadProtector;
import com.ecommerce.authuser.rbac.domain.Role;
import com.ecommerce.authuser.rbac.domain.ScopeType;
import com.ecommerce.authuser.rbac.repository.RoleRepository;
import com.ecommerce.authuser.rbac.repository.UserRoleRepository;
import com.ecommerce.authuser.security.repository.LoginAttemptRepository;
import com.ecommerce.authuser.security.service.AuditValueHasher;
import com.ecommerce.authuser.user.domain.User;
import com.ecommerce.authuser.user.repository.UserRepository;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GoogleSigninServiceTest {

    @Test
    void signin_newGoogleIdentity_createsVerifiedBuyerAndIssuesInternalTokens() {
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        ExternalIdentityRepository externalIdentities = mock(ExternalIdentityRepository.class);
        UserRepository users = mock(UserRepository.class);
        RoleRepository roles = mock(RoleRepository.class);
        UserRoleRepository userRoles = mock(UserRoleRepository.class);
        SessionTokenIssuer tokens = mock(SessionTokenIssuer.class);
        LoginAttemptRepository loginAttempts = mock(LoginAttemptRepository.class);
        AuditValueHasher auditHasher = mock(AuditValueHasher.class);
        TwoFactorCredentialRepository twoFactorCredentials = mock(TwoFactorCredentialRepository.class);
        MfaChallengeRepository mfaChallenges = mock(MfaChallengeRepository.class);
        OutboxEventRepository outboxEvents = mock(OutboxEventRepository.class);
        OutboxPayloadProtector payloadProtector = mock(OutboxPayloadProtector.class);

        GoogleSigninService service = new GoogleSigninService(
                verifier, externalIdentities, users, roles, userRoles, tokens, loginAttempts,
                auditHasher, twoFactorCredentials, mfaChallenges, new IdentityNormalizer(),
                outboxEvents, payloadProtector);

        when(verifier.verify("google-token"))
                .thenReturn(new GoogleIdentity("google-subject", "new@example.com", "New User"));
        when(externalIdentities.findByProviderAndProviderSubject(
                ExternalIdentityProvider.GOOGLE, "google-subject")).thenReturn(Optional.empty());
        when(users.findByEmailNormalizedForUpdate("new@example.com")).thenReturn(Optional.empty());
        when(roles.findByRoleKey("BUYER"))
                .thenReturn(Optional.of(Role.create("BUYER", ScopeType.SYSTEM, "Buyer", true)));
        when(userRoles.findAllByUser_IdAndRevokedAtIsNull(any())).thenReturn(List.of());
        when(twoFactorCredentials.findByUserIdForUpdate(any())).thenReturn(Optional.empty());
        when(tokens.issue(any(User.class), any(Instant.class)))
                .thenReturn(new SessionTokenPair("access", "refresh", 900, 2_592_000));
        when(auditHasher.hash(anyString())).thenReturn("a".repeat(64));
        when(payloadProtector.protect(anyString(), any())).thenReturn(Map.of("safe", true));

        GoogleSigninResult result = service.signin(new GoogleSigninCommand(
                "google-token", "127.0.0.1", "JUnit"));

        assertTrue(result.created());
        assertEquals("new@example.com", result.email());
        assertTrue(result.emailVerified());
        assertEquals("access", result.accessToken());
        assertEquals("refresh", result.refreshToken());
        verify(users).save(any(User.class));
        verify(externalIdentities).save(any(ExternalIdentity.class));
        verify(outboxEvents).save(any());
    }

    @Test
    void signin_existingGoogleIdentity_doesNotCreateAnotherUser() {
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        ExternalIdentityRepository externalIdentities = mock(ExternalIdentityRepository.class);
        UserRepository users = mock(UserRepository.class);
        RoleRepository roles = mock(RoleRepository.class);
        UserRoleRepository userRoles = mock(UserRoleRepository.class);
        SessionTokenIssuer tokens = mock(SessionTokenIssuer.class);
        LoginAttemptRepository loginAttempts = mock(LoginAttemptRepository.class);
        AuditValueHasher auditHasher = mock(AuditValueHasher.class);
        TwoFactorCredentialRepository twoFactorCredentials = mock(TwoFactorCredentialRepository.class);
        MfaChallengeRepository mfaChallenges = mock(MfaChallengeRepository.class);
        OutboxEventRepository outboxEvents = mock(OutboxEventRepository.class);
        OutboxPayloadProtector payloadProtector = mock(OutboxPayloadProtector.class);
        GoogleSigninService service = new GoogleSigninService(
                verifier, externalIdentities, users, roles, userRoles, tokens, loginAttempts,
                auditHasher, twoFactorCredentials, mfaChallenges, new IdentityNormalizer(),
                outboxEvents, payloadProtector);

        User user = User.registerBuyer("returning@example.com", "returning@example.com", null,
                "Returning User", null, null);
        user.verifyEmail(Instant.now());
        ExternalIdentity identity = ExternalIdentity.linkGoogle(user, "google-subject", "old@example.com", Instant.now());

        when(verifier.verify("google-token"))
                .thenReturn(new GoogleIdentity("google-subject", "returning@example.com", "Returning User"));
        when(externalIdentities.findByProviderAndProviderSubject(
                ExternalIdentityProvider.GOOGLE, "google-subject")).thenReturn(Optional.of(identity));
        when(userRoles.findAllByUser_IdAndRevokedAtIsNull(any())).thenReturn(List.of());
        when(twoFactorCredentials.findByUserIdForUpdate(any())).thenReturn(Optional.empty());
        when(tokens.issue(any(User.class), any(Instant.class)))
                .thenReturn(new SessionTokenPair("access", "refresh", 900, 2_592_000));
        when(auditHasher.hash(anyString())).thenReturn("b".repeat(64));

        GoogleSigninResult result = service.signin(new GoogleSigninCommand(
                "google-token", "127.0.0.1", null));

        assertFalse(result.created());
        assertEquals(user.getId(), result.userId());
        assertNull(user.getPasswordHash());
        verify(users, org.mockito.Mockito.never()).save(any());
        verify(loginAttempts).save(any());
    }
}
