package com.ecommerce.authuser.auth.google;

import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class GoogleAuthorizationCodeClient implements GoogleAuthorizationCodeExchangeClient {

    private static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    private final GoogleIdTokenProperties properties;

    @Override
    public String exchange(String code, String codeVerifier) {
        if (!properties.codeFlowConfigured()) {
            throw new GoogleSigninUnavailableException();
        }
        try {
            LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("code", code);
            form.add("client_id", properties.resolvedAuthorizationClientId());
            form.add("client_secret", properties.resolvedAuthorizationClientSecret());
            form.add("redirect_uri", properties.resolvedAuthorizationRedirectUri());
            form.add("grant_type", "authorization_code");
            form.add("code_verifier", codeVerifier);
            Map<?, ?> response = RestClient.create().post().uri(TOKEN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form).retrieve().body(Map.class);
            Object idToken = response == null ? null : response.get("id_token");
            if (!(idToken instanceof String value) || value.isBlank()) {
                throw new InvalidGoogleIdTokenException();
            }
            return value;
        } catch (InvalidGoogleIdTokenException | GoogleSigninUnavailableException ex) {
            throw ex;
        } catch (RuntimeException ex) {
            throw new InvalidGoogleIdTokenException(ex);
        }
    }
}
