<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

final readonly class TotpKeyring
{
    private const int KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;

    /** @var non-empty-array<string, string> */
    private array $keys;

    /**
     * @param non-empty-array<string, string> $keys
     */
    public function __construct(
        public string $currentKeyId,
        array $keys,
    ) {
        if (!array_key_exists($this->currentKeyId, $keys)) {
            throw new \InvalidArgumentException(
                'Current TOTP key must exist in the keyring.',
            );
        }

        foreach ($keys as $id => $key) {
            if (
                preg_match('/\A[A-Za-z0-9._-]{1,64}\z/D', $id) !== 1
                || strlen($key) !== self::KEY_BYTES
            ) {
                throw new \InvalidArgumentException(
                    'TOTP keyring contains an invalid key.',
                );
            }
        }

        $this->keys = $keys;
    }

    /**
     * @return array{keyId: string, nonce: string, ciphertext: string}
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $secret,
        string $subjectId,
    ): array {
        if ($secret === '') {
            throw new \InvalidArgumentException('TOTP secret is empty.');
        }

        $nonce = random_bytes(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
        );
        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $secret,
            self::aad($subjectId),
            $nonce,
            $this->keys[$this->currentKeyId],
        );

        return [
            'keyId' => $this->currentKeyId,
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertext),
        ];
    }

    public function decrypt(
        string $keyId,
        string $nonce,
        #[\SensitiveParameter]
        string $ciphertext,
        string $subjectId,
    ): string {
        $key = $this->keys[$keyId] ?? null;

        if ($key === null) {
            throw new \RuntimeException('TOTP encryption key is unavailable.');
        }

        $decodedNonce = base64_decode($nonce, true);
        $decodedCiphertext = base64_decode($ciphertext, true);

        if (
            !is_string($decodedNonce)
            || strlen($decodedNonce)
                !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
            || !is_string($decodedCiphertext)
        ) {
            throw new \UnexpectedValueException(
                'Persisted TOTP ciphertext is invalid.',
            );
        }

        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $decodedCiphertext,
            self::aad($subjectId),
            $decodedNonce,
            $key,
        );

        if (!is_string($plain) || $plain === '') {
            throw new \UnexpectedValueException(
                'Persisted TOTP ciphertext could not be authenticated.',
            );
        }

        return $plain;
    }

    private static function aad(string $subjectId): string
    {
        return "componenta-auth-totp-v1\0" . $subjectId;
    }
}
