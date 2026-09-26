CREATE TABLE auth_totp_credentials (
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    created_at DATETIME(6) NOT NULL,
    active_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    active_nonce VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    active_ciphertext TEXT NULL,
    active_digits TINYINT UNSIGNED NULL,
    active_period SMALLINT UNSIGNED NULL,
    active_digest VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    enabled_at DATETIME(6) NULL,
    last_used_step BIGINT UNSIGNED NULL,
    pending_key_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    pending_nonce VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
    pending_ciphertext TEXT NULL,
    pending_digits TINYINT UNSIGNED NULL,
    pending_period SMALLINT UNSIGNED NULL,
    pending_digest VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NULL,
    pending_created_at DATETIME(6) NULL
) ENGINE=InnoDB;
