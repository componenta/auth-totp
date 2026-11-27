# Componenta Auth TOTP

Encrypted TOTP enrollment and reauthentication for Componenta Auth 4.

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

Enrollment activation checks both the pending TTL and the accepted code step
after its conditional write, before committing. A late activation is rolled back,
including any replacement of the existing factor. Verification checks the
configured time window after its claim commits; an expired proof returns `false`
and the claimed step remains consumed. Clock failures propagate; they roll back
an uncommitted activation but cannot undo a committed verification claim.

Pending and active credentials use the same persisted-parameter validation as
`TotpCredential`: 6–8 digits, a 15–120 second period, and SHA-1, SHA-256 or SHA-512
(case-insensitive). Invalid stored parameters raise `InvalidArgumentException`
before secret verification or a state update. Rejected enrollment preserves the
existing factor; rejected verification leaves the replay counter unchanged.

## Requirements

PHP 8.4 or newer and the coordinated Componenta Auth 4 dependencies:
`componenta/auth ^4.0.0`, `componenta/auth-session ^2.0.0` and
`componenta/auth-session-http ^3.0.0`. The browser transport uses
`componenta/http-csrf-middleware ^4.0.0`. Unsafe CSRF-protected requests require
valid Origin/Referer evidence and an admitted CSRF token.

Upgrade these packages together. Session issuance uses the shared Componenta
Auth session APIs. See [CHANGELOG.md](CHANGELOG.md) for migration details.
