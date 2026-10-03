package com.ecommerce.authuser.integration.auth;

import com.ecommerce.authuser.auth.security.TokenHasher;
import com.ecommerce.authuser.support.base.BaseIntegrationTest;
import com.ecommerce.authuser.token.domain.PasswordResetToken;
import com.ecommerce.authuser.token.repository.PasswordResetTokenRepository;
import com.ecommerce.authuser.user.domain.User;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordResetIntegrationTest extends BaseIntegrationTest {

    private static final String SIGNUP_URL = "/api/v1/auth/signup";
    private static final String RESET_URL = "/api/v1/auth/password/reset";
    private static final String REFRESH_URL = "/api/v1/auth/refresh";
    private static final String INITIAL_PASSWORD = "InitialPassword#2026";
    private static final String NEW_PASSWORD = "NewPassword#2026";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenHasher tokenHasher;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Test
    void resetPassword_shouldRevokeOldSessionAndIssueNewTokenPair() throws Exception {
        String email = "reset-" + UUID.randomUUID() + "@example.com";
        String phone = "+849" + String.format(
                "%08d",
                Math.abs(UUID.randomUUID().getMostSignificantBits()) % 100000000
        );
        String oldRefreshToken = signup(email, phone);
        String rawResetToken = "reset-token-" + UUID.randomUUID();
        User user = userRepository
                .findByEmailNormalizedAndDeletedAtIsNull(email)
                .orElseThrow();

        passwordResetTokenRepository.saveAndFlush(
                PasswordResetToken.create(
                        user,
                        tokenHasher.hash(rawResetToken),
                        Instant.now().plus(5, ChronoUnit.MINUTES)
                )
        );

        String resetResponse = mockMvc.perform(
                        post(RESET_URL)
                                .header("X-Request-ID", "reset-request-id")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "token": "%s",
                                          "new_password": "%s"
                                        }
                                        """.formatted(rawResetToken, NEW_PASSWORD))
                )
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Pragma", "no-cache"))
                .andExpect(jsonPath("$.data.tokens.token_type").value("Bearer"))
                .andExpect(jsonPath("$.data.tokens.access_token").value(not(emptyOrNullString())))
                .andExpect(jsonPath("$.data.tokens.refresh_token").value(not(emptyOrNullString())))
                .andExpect(jsonPath("$.data.tokens.expires_in").value(900))
                .andExpect(jsonPath("$.data.tokens.refresh_expires_in").value(2592000))
                .andExpect(jsonPath("$.meta.request_id").value("reset-request-id"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        String newRefreshToken = new tools.jackson.databind.ObjectMapper()
                .readTree(resetResponse)
                .path("data")
                .path("tokens")
                .path("refresh_token")
                .asText();

        mockMvc.perform(
                        post(REFRESH_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "refresh_token": "%s"
                                        }
                                        """.formatted(oldRefreshToken))
                )
                .andExpect(status().isUnauthorized());

        mockMvc.perform(
                        post(REFRESH_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "refresh_token": "%s"
                                        }
                                        """.formatted(newRefreshToken))
                )
                .andExpect(status().isOk());
    }

    private String signup(String email, String phone) throws Exception {
        String response = mockMvc.perform(
                        post(SIGNUP_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "full_name": "Password Reset Test User",
                                          "email": "%s",
                                          "password": "%s",
                                          "phone": "%s"
                                        }
                                        """.formatted(email, INITIAL_PASSWORD, phone))
                )
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return new tools.jackson.databind.ObjectMapper()
                .readTree(response)
                .path("data")
                .path("tokens")
                .path("refresh_token")
                .asText();
    }
}
