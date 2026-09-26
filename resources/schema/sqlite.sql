CREATE TABLE auth_totp_credentials (
    subject_uuid TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    active_key_id TEXT NULL,
    active_nonce TEXT NULL,
    active_ciphertext TEXT NULL,
    active_digits INTEGER NULL,
    active_period INTEGER NULL,
    active_digest TEXT NULL,
    enabled_at TEXT NULL,
    last_used_step INTEGER NULL,
    pending_key_id TEXT NULL,
    pending_nonce TEXT NULL,
    pending_ciphertext TEXT NULL,
    pending_digits INTEGER NULL,
    pending_period INTEGER NULL,
    pending_digest TEXT NULL,
    pending_created_at TEXT NULL
);
