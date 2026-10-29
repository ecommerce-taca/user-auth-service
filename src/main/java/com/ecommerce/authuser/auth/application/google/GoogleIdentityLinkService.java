package com.ecommerce.authuser.auth.application.google;

import com.ecommerce.authuser.auth.externalidentity.ExternalIdentity;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityProvider;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityRepository;
import com.ecommerce.authuser.auth.google.GoogleIdTokenVerifier;
import com.ecommerce.authuser.auth.google.GoogleIdentity;
import com.ecommerce.authuser.user.exception.profile.UserNotFoundException;
import com.ecommerce.authuser.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class GoogleIdentityLinkService {

    private final GoogleIdTokenVerifier googleIdTokenVerifier;
    private final ExternalIdentityRepository externalIdentityRepository;
    private final UserRepository userRepository;

    @Transactional
    public boolean link(UUID userId, String idToken) {
        GoogleIdentity googleIdentity = googleIdTokenVerifier.verify(idToken);
        Instant now = Instant.now();

        var user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(UserNotFoundException::new);

        var existing = externalIdentityRepository.findByProviderAndProviderSubject(
                ExternalIdentityProvider.GOOGLE, googleIdentity.subject());

        if (existing.isPresent()) {
            if (existing.get().getUser().getId().equals(user.getId())) {
                existing.get().recordAuthentication(googleIdentity.email(), now);
                return false;
            }
            throw new GoogleIdentityAlreadyLinkedException();
        }

        externalIdentityRepository.save(ExternalIdentity.linkGoogle(
                user, googleIdentity.subject(), googleIdentity.email(), now));
        return true;
    }
}
