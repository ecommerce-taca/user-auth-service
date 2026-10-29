package com.ecommerce.authuser.auth.google;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GoogleAuthorizationServiceTest {

    private final GoogleIdTokenProperties properties = new GoogleIdTokenProperties(
            java.util.List.of("web-client.apps.googleusercontent.com"), null,
            "web-client.apps.googleusercontent.com", "server-only-secret",
            "http://localhost:8081/api/v1/auth/google/callback", false);

    @Test
    void begin_setsStateCookieAndBuildsPkceAuthorizationUrl() {
        GoogleAuthorizationService service = new GoogleAuthorizationService(properties,
                mock(GoogleAuthorizationCodeExchangeClient.class));
        MockHttpServletResponse response = new MockHttpServletResponse();

        String location = service.begin(response);

        assertTrue(location.startsWith("https://accounts.google.com/o/oauth2/v2/auth?"));
        assertTrue(location.contains("client_id=web-client.apps.googleusercontent.com"));
        assertTrue(location.contains("code_challenge_method=S256"));
        assertEquals(1, response.getCookies().length);
        assertEquals(GoogleAuthorizationService.STATE_COOKIE, response.getCookies()[0].getName());
        assertTrue(response.getCookies()[0].isHttpOnly());
    }

    @Test
    void exchange_matchingState_exchangesCodeUsingVerifierFromCookie() {
        GoogleAuthorizationCodeExchangeClient client = mock(GoogleAuthorizationCodeExchangeClient.class);
        GoogleAuthorizationService service = new GoogleAuthorizationService(properties, client);
        MockHttpServletResponse startResponse = new MockHttpServletResponse();
        String location = service.begin(startResponse);
        String state = location.replaceFirst(".*[?&]state=([^&]+).*", "$1");
        String[] stateAndVerifier = startResponse.getCookies()[0].getValue().split("\\.", 2);
        MockHttpServletRequest callbackRequest = new MockHttpServletRequest();
        callbackRequest.setCookies(startResponse.getCookies());
        MockHttpServletResponse callbackResponse = new MockHttpServletResponse();
        when(client.exchange("authorization-code", stateAndVerifier[1])).thenReturn("google-id-token");

        String token = service.exchange(callbackRequest, callbackResponse, "authorization-code", state);

        assertEquals("google-id-token", token);
        verify(client).exchange("authorization-code", stateAndVerifier[1]);
        assertEquals(0, callbackResponse.getCookies()[0].getMaxAge());
    }
}
