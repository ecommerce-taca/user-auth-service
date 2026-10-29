package com.ecommerce.authuser.auth.google;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class GoogleAuthorizationService {

    public static final String STATE_COOKIE = "google_oauth_state";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final GoogleIdTokenProperties properties;
    private final GoogleAuthorizationCodeExchangeClient codeExchangeClient;

    public String begin(HttpServletResponse response) {
        if (!properties.codeFlowConfigured()) {
            throw new GoogleSigninUnavailableException();
        }
        String state = randomUrlValue();
        String verifier = randomUrlValue();
        addStateCookie(response, state + "." + verifier, Duration.ofMinutes(10));
        String challenge = sha256UrlValue(verifier);
        return UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
                .queryParam("client_id", properties.resolvedAuthorizationClientId())
                .queryParam("redirect_uri", properties.resolvedAuthorizationRedirectUri())
                .queryParam("response_type", "code")
                .queryParam("scope", "openid email profile")
                .queryParam("state", state)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("prompt", "select_account")
                .build().encode().toUriString();
    }

    public String exchange(HttpServletRequest request, HttpServletResponse response, String code, String state) {
        if (code == null || code.isBlank() || state == null || state.isBlank()) {
            throw new InvalidGoogleIdTokenException();
        }
        String cookie = findStateCookie(request);
        clearStateCookie(response);
        if (cookie == null) {
            throw new InvalidGoogleIdTokenException();
        }
        int separator = cookie.indexOf('.');
        if (separator < 1 || separator == cookie.length() - 1) {
            throw new InvalidGoogleIdTokenException();
        }
        String expectedState = cookie.substring(0, separator);
        if (!MessageDigest.isEqual(expectedState.getBytes(StandardCharsets.US_ASCII),
                state.getBytes(StandardCharsets.US_ASCII))) {
            throw new InvalidGoogleIdTokenException();
        }
        return codeExchangeClient.exchange(code, cookie.substring(separator + 1));
    }

    private String findStateCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if (STATE_COOKIE.equals(cookie.getName())) return cookie.getValue();
        }
        return null;
    }

    private void clearStateCookie(HttpServletResponse response) {
        addStateCookie(response, "", Duration.ZERO);
    }

    private void addStateCookie(HttpServletResponse response, String value, Duration maxAge) {
        response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(STATE_COOKIE, value)
                .httpOnly(true).secure(properties.resolvedAuthorizationCookieSecure())
                .sameSite("Lax").path("/api/v1/auth/google/").maxAge(maxAge).build().toString());
    }

    private static String randomUrlValue() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String sha256UrlValue(String value) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
