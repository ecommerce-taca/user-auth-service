package com.ecommerce.authuser.integration.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;

import com.ecommerce.authuser.support.base.BaseIntegrationTest;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PasswordChangeIntegrationTest extends BaseIntegrationTest {

    private static final String SIGNUP_URL = "/api/v1/auth/signup";
    private static final String SIGNIN_URL = "/api/v1/auth/signin";
    private static final String CHANGE_URL = "/api/v1/auth/password/change";
    private static final String REFRESH_URL = "/api/v1/auth/refresh";
    private static final String INITIAL_PASSWORD = "InitialPassword#2026";
    private static final String NEW_PASSWORD = "ChangedPassword#2026";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void changePassword_shouldKeepCurrentSessionAndRevokeOtherSessions() throws Exception {
        String email = uniqueEmail();
        String phone = uniquePhone();
        SessionTokens otherSession = signup(email, phone);
        SessionTokens currentSession = signin(email, INITIAL_PASSWORD);

        mockMvc.perform(
                        post(CHANGE_URL)
                                .header("Authorization", "Bearer " + currentSession.accessToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "current_password": "%s",
                                          "new_password": "%s",
                                          "all_sessions": false
                                        }
                                        """.formatted(INITIAL_PASSWORD, NEW_PASSWORD))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.all_sessions").value(false))
                .andExpect(jsonPath("$.data.sessions_revoked").value(1));

        refresh(otherSession.refreshToken(), status().isUnauthorized());
        refresh(currentSession.refreshToken(), status().isOk());
        signinExpectStatus(email, INITIAL_PASSWORD, status().isUnauthorized());
        signinExpectStatus(email, NEW_PASSWORD, status().isOk());
    }

    @Test
    void changePassword_allSessionsWithoutStepUp_shouldRequireMfaAndPreserveSessions() throws Exception {
        String email = uniqueEmail();
        SessionTokens session = signup(email, uniquePhone());

        mockMvc.perform(
                        post(CHANGE_URL)
                                .header("Authorization", "Bearer " + session.accessToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "current_password": "%s",
                                          "new_password": "%s",
                                          "all_sessions": true
                                        }
                                        """.formatted(INITIAL_PASSWORD, NEW_PASSWORD))
                )
                .andExpect(status().isPreconditionRequired())
                .andExpect(jsonPath("$.error.code").value("RBAC_MFA_REQUIRED"));

        refresh(session.refreshToken(), status().isOk());
        signinExpectStatus(email, INITIAL_PASSWORD, status().isOk());
    }

    private SessionTokens signup(String email, String phone) throws Exception {
        String response = mockMvc.perform(
                        post(SIGNUP_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "full_name": "Password Change Test User",
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

        return readTokens(response);
    }

    private SessionTokens signin(String email, String password) throws Exception {
        String response = mockMvc.perform(
                        post(SIGNIN_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "identifier": "%s",
                                          "password": "%s"
                                        }
                                        """.formatted(email, password))
                )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return readTokens(response);
    }

    private void refresh(String refreshToken, ResultMatcher expectedStatus) throws Exception {
        mockMvc.perform(
                        post(REFRESH_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "refresh_token": "%s"
                                        }
                                        """.formatted(refreshToken))
                )
                .andExpect(expectedStatus);
    }

    private void signinExpectStatus(String email, String password, ResultMatcher expectedStatus) throws Exception {
        mockMvc.perform(
                        post(SIGNIN_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "identifier": "%s",
                                          "password": "%s"
                                        }
                                        """.formatted(email, password))
                )
                .andExpect(expectedStatus);
    }

    private SessionTokens readTokens(String response) throws Exception {
        tools.jackson.databind.JsonNode tokens = new tools.jackson.databind.ObjectMapper()
                .readTree(response)
                .path("data")
                .path("tokens");

        return new SessionTokens(
                tokens.path("access_token").asText(),
                tokens.path("refresh_token").asText()
        );
    }

    private String uniqueEmail() {
        return "password-change-" + UUID.randomUUID() + "@example.com";
    }

    private String uniquePhone() {
        long number = Math.abs(UUID.randomUUID().getMostSignificantBits()) % 100000000;
        return "+849" + String.format("%08d", number);
    }

    private record SessionTokens(String accessToken, String refreshToken) {
    }
}
