package com.ecommerce.authuser.integration.auth;

import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityProvider;
import com.ecommerce.authuser.auth.externalidentity.ExternalIdentityRepository;
import com.ecommerce.authuser.auth.google.GoogleIdTokenVerifier;
import com.ecommerce.authuser.auth.google.GoogleIdentity;
import com.ecommerce.authuser.support.base.BaseIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class GoogleSigninIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ExternalIdentityRepository externalIdentityRepository;

    @MockitoBean
    private GoogleIdTokenVerifier googleIdTokenVerifier;

    @Test
    void googleSignin_newIdentity_createsVerifiedBuyerAndInternalSession() throws Exception {
        String subject = "google-" + UUID.randomUUID();
        String email = "google-" + UUID.randomUUID() + "@example.com";
        when(googleIdTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleIdentity(subject, email, "Google Test User"));

        mockMvc.perform(post("/api/v1/auth/google")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                { "id_token": "google-id-token" }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.created").value(true))
                .andExpect(jsonPath("$.data.user.email").value(email))
                .andExpect(jsonPath("$.data.user.email_verified").value(true))
                .andExpect(jsonPath("$.data.user.roles[0]").value("BUYER"))
                .andExpect(jsonPath("$.data.tokens.access_token").isNotEmpty())
                .andExpect(jsonPath("$.data.tokens.refresh_token").isNotEmpty());

        var user = userRepository.findByEmailNormalizedAndDeletedAtIsNull(email).orElseThrow();
        assertThat(user.getPasswordHash()).isNull();
        assertThat(user.getEmailVerifiedAt()).isNotNull();
        assertThat(externalIdentityRepository.findByProviderAndProviderSubject(
                ExternalIdentityProvider.GOOGLE, subject)).isPresent();
    }
}
