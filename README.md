# Componenta Auth TOTP

Encrypted TOTP enrollment and reauthentication for Componenta Auth 3.

The package uses `spomky-labs/otphp` for RFC 6238 verification and libsodium
XChaCha20-Poly1305 for secret encryption at rest.

Security properties:

- raw TOTP secrets are returned only during enrollment and are never stored;
- database rows contain authenticated ciphertext + nonce + key id;
- accepted time steps are persisted and cannot be replayed;
- enrollment must be confirmed with a valid code before the credential becomes active;
- TOTP evidence adds a possession factor but never claims phishing resistance;
- successful reauthentication rotates the active `SessionCredential`.
