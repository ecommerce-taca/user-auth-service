# Google Sign-In contract

Google is an identity provider only. This service verifies the Google ID token and
then issues the same internal access JWT and rotating refresh token as password
signin. Clients must never use a Google access token as an API bearer token.

## `POST /api/v1/auth/google`

Public endpoint. The frontend obtains an ID token from Google Identity Services
and sends it directly to the auth service over HTTPS.

```json
{
  "id_token": "eyJ..."
}
```

The service verifies the JWT signature from Google's JWKS and requires a valid
Google issuer (`accounts.google.com` or `https://accounts.google.com`), expiry,
an allowed OAuth client ID in `aud`, a non-empty `sub`, and an email claim
marked `email_verified=true`.

- A known `(GOOGLE, sub)` signs in.
- An unknown Google identity whose email does not exist creates a verified
  `BUYER` account and returns `created: true`.
- If the email already belongs to a local account, the endpoint returns `409`
  with `AUTH_GOOGLE_LINK_REQUIRED`; it never auto-links by email.
- A user with admin MFA enabled receives the existing `AUTH_MFA_REQUIRED`
  response and must complete `POST /api/v1/auth/2fa/verify` with purpose `LOGIN`.

Successful response (`200`):

```json
{
  "data": {
    "user": {
      "id": "019...",
      "full_name": "Nguyen Van A",
      "email": "user@example.com",
      "email_verified": true,
      "phone": null,
      "phone_verified": false,
      "roles": ["BUYER"],
      "status": "ACTIVE"
    },
    "tokens": {
      "token_type": "Bearer",
      "access_token": "...",
      "expires_in": 900,
      "refresh_token": "...",
      "refresh_expires_in": 2592000
    },
    "created": true
  },
  "meta": { "request_id": "..." }
}
```

Errors callers must handle: `AUTH_GOOGLE_TOKEN_INVALID` (`401`),
`AUTH_GOOGLE_UNAVAILABLE` (`503`), `AUTH_GOOGLE_LINK_REQUIRED` (`409`), and the
existing account status/MFA errors.

## `POST /api/v1/auth/identities/google/link`

Authenticated endpoint for a user who first signed in with an existing local
method and wants to enable Google sign-in.

```json
{
  "id_token": "eyJ..."
}
```

It returns `{ "data": { "linked": true } }`. Repeating the same link for the
same user is idempotent and returns `linked: false`. If that Google identity is
linked to another user, the service returns `409 AUTH_GOOGLE_IDENTITY_LINKED`.

## Browser callback (authorization-code flow)

This flow is available when the backend is configured with its OAuth web-client
ID, client secret, and exact redirect URI.

1. Navigate the browser to `GET /api/v1/auth/google/authorize`.
2. The service sets a short-lived, HttpOnly, `SameSite=Lax` state cookie and
   redirects to Google with PKCE (`S256`).
3. Google redirects to `GET /api/v1/auth/google/callback?code=...&state=...`.
4. The callback verifies `state`, exchanges the code server-to-server with
   Google, validates the received ID token, and responds with the same JSON
   session payload as `POST /api/v1/auth/google`.

Register the exact backend callback URL in Google Cloud Console. Examples:

```text
http://localhost:8081/api/v1/auth/google/callback
https://api.example.com/api/v1/auth/google/callback
```

The redirect URI must exactly match the configured
`AUTH_GOOGLE_AUTHORIZATION_REDIRECT_URI`, including scheme, host, path and
trailing slash behavior. The client secret is server-only and must be stored in
the deployment secret, never in frontend code or Git.

## Client handling

Store this service's refresh token according to the application's established
session policy. Do not persist, log, or send the Google ID token again after the
one-time request. For an account-link-required response, ask the user to sign in
using their existing method, then call the link endpoint with a freshly obtained
Google ID token.
