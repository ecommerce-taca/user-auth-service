package com.ecommerce.authuser.auth.google;

public interface GoogleIdTokenVerifier {

    GoogleIdentity verify(String idToken);
}
