CREATE TABLE auth_totp_credentials (
    subject_uuid UUID PRIMARY KEY,
    created_at TIMESTAMP(6) WITHOUT TIME ZONE NOT NULL,
    active_key_id VARCHAR(64) NULL,
    active_nonce VARCHAR(64) NULL,
    active_ciphertext TEXT NULL,
    active_digits SMALLINT NULL,
    active_period SMALLINT NULL,
    active_digest VARCHAR(16) NULL,
    enabled_at TIMESTAMP(6) WITHOUT TIME ZONE NULL,
    last_used_step BIGINT NULL,
    pending_key_id VARCHAR(64) NULL,
    pending_nonce VARCHAR(64) NULL,
    pending_ciphertext TEXT NULL,
    pending_digits SMALLINT NULL,
    pending_period SMALLINT NULL,
    pending_digest VARCHAR(16) NULL,
    pending_created_at TIMESTAMP(6) WITHOUT TIME ZONE NULL
);
