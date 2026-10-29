package com.ecommerce.authuser.auth.google;

public interface GoogleAuthorizationCodeExchangeClient {

    String exchange(String code, String codeVerifier);
}
