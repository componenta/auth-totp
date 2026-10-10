# Componenta Auth TOTP

Encrypted TOTP enrollment and reauthentication for Componenta Auth 3.

The package uses `spomky-labs/otphp` for RFC 6238 verification and libsodium
XChaCha20-Poly1305 for secret encryption at rest.

Security properties:

- raw TOTP secrets are returned only during enrollment and are never stored;
- database rows contain authenticated ciphertext + nonce + key id;
- accepted time steps are persisted and cannot be replayed;
- enrollment must be confirmed with a valid code before the credential becomes active;
- pending enrollment secrets expire after a bounded server-side TTL (10 minutes by default);
- TOTP evidence adds a possession factor but never claims phishing resistance;
- successful reauthentication rotates the active `SessionCredential`.

## Version 2 compatibility

Version 2.0.0 requires `componenta/auth-session-http ^2.0.1` and the CSRF v3
browser security model. Unsafe protected requests require valid Origin/Referer
evidence and a valid CSRF token; an omitted origin must never be accepted by
default. Auth's session-issuance contract remains unchanged.

See [CHANGELOG.md](CHANGELOG.md) for migration details and the verified
security-admission tests.
