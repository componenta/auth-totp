<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use Cycle\Database\Query\OnConflict;
use DateTimeImmutable;
use DateTimeZone;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;

final readonly class DatabaseTotpManager implements TotpManagerInterface
{
    private const int DEFAULT_DIGITS = 6;
    private const int DEFAULT_PERIOD = 30;
    private const string DEFAULT_DIGEST = 'sha1';
    private const int SECRET_BYTES = 32;
    private const string DATE_FORMAT = 'Y-m-d H:i:s.u';

    public function __construct(
        private DatabaseInterface $database,
        private ClockInterface $clock,
        private TotpKeyring $keyring,
        private string $table = 'auth_totp_credentials',
        private int $window = 1,
        private int $enrollmentTtlSeconds = 600,
    ) {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $this->table) !== 1) {
            throw new \InvalidArgumentException(
                'TOTP table name is invalid.',
            );
        }

        if ($this->window < 0 || $this->window > 2) {
            throw new \InvalidArgumentException(
                'TOTP verification window must be between 0 and 2 steps.',
            );
        }

        if (
            $this->enrollmentTtlSeconds < 60
            || $this->enrollmentTtlSeconds > 3600
        ) {
            throw new \InvalidArgumentException(
                'TOTP enrollment TTL must be between 60 and 3600 seconds.',
            );
        }
    }

    #[\Override]
    public function beginEnrollment(
        UuidInterface $subjectId,
        string $label,
        string $issuer,
    ): TotpEnrollment {
        self::assertLabel($label, 'TOTP label');
        self::assertLabel($issuer, 'TOTP issuer');

        /** @var non-empty-string $label */
        /** @var non-empty-string $issuer */
        $otp = TOTP::generate($this->clock, self::SECRET_BYTES)
            ->withDigits(self::DEFAULT_DIGITS)
            ->withPeriod(self::DEFAULT_PERIOD)
            ->withDigest(self::DEFAULT_DIGEST)
            ->withLabel($label)
            ->withIssuer($issuer);
        $secret = $otp->getSecret();
        $encrypted = $this->keyring->encrypt(
            $secret,
            $subjectId->toString(),
        );
        $now = $this->format($this->now());

        $this->database->insert($this->table)->values([
            'subject_uuid' => $subjectId->toString(),
            'pending_key_id' => $encrypted['keyId'],
            'pending_nonce' => $encrypted['nonce'],
            'pending_ciphertext' => $encrypted['ciphertext'],
            'pending_digits' => self::DEFAULT_DIGITS,
            'pending_period' => self::DEFAULT_PERIOD,
            'pending_digest' => self::DEFAULT_DIGEST,
            'pending_created_at' => $now,
            'created_at' => $now,
        ])->onConflict(
            OnConflict::target('subject_uuid')->doUpdate([
                'pending_key_id',
                'pending_nonce',
                'pending_ciphertext',
                'pending_digits',
                'pending_period',
                'pending_digest',
                'pending_created_at',
            ]),
        )->run();

        return new TotpEnrollment(
            secret: $secret,
            provisioningUri: $otp->getProvisioningUri(),
        );
    }

    #[\Override]
    public function confirmEnrollment(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $code,
    ): bool {
        if (!self::validCodeShape($code)) {
            return false;
        }

        return $this->database->transaction(function () use (
            $subjectId,
            $code,
        ): bool {
            $row = $this->row($subjectId);

            if (
                $row === null
                || ($row['pending_ciphertext'] ?? null) === null
            ) {
                return false;
            }

            $subject = $subjectId->toString();
            $pendingCiphertext = self::stringValue(
                $row,
                'pending_ciphertext',
            );
            $pendingCreatedAt = $this->date(
                self::stringValue($row, 'pending_created_at'),
            );
            $now = $this->now();

            if (
                $pendingCreatedAt->modify(
                    sprintf('+%d seconds', $this->enrollmentTtlSeconds),
                ) <= $now
            ) {
                $this->clearPending($subject, $pendingCiphertext);

                return false;
            }

            $digits = self::intValue($row, 'pending_digits');
            $period = self::intValue($row, 'pending_period');
            $digest = self::stringValue($row, 'pending_digest');

            if (!self::validCode($code, $digits)) {
                return false;
            }

            $secret = $this->keyring->decrypt(
                self::stringValue($row, 'pending_key_id'),
                self::stringValue($row, 'pending_nonce'),
                self::stringValue($row, 'pending_ciphertext'),
                $subject,
            );

            try {
                $step = $this->matchingStep(
                    $secret,
                    $digits,
                    $period,
                    $digest,
                    $code,
                    null,
                );
            } finally {
                sodium_memzero($secret);
            }

            if ($step === null) {
                return false;
            }

            $formattedNow = $this->format($now);
            $affected = $this->database->update($this->table)
                ->where('subject_uuid', $subject)
                ->where('pending_ciphertext', $pendingCiphertext)
                ->values([
                    'active_key_id' => self::stringValue(
                        $row,
                        'pending_key_id',
                    ),
                    'active_nonce' => self::stringValue(
                        $row,
                        'pending_nonce',
                    ),
                    'active_ciphertext' => $pendingCiphertext,
                    'active_digits' => $digits,
                    'active_period' => $period,
                    'active_digest' => $digest,
                    'enabled_at' => $formattedNow,
                    'last_used_step' => $step,
                    'pending_key_id' => null,
                    'pending_nonce' => null,
                    'pending_ciphertext' => null,
                    'pending_digits' => null,
                    'pending_period' => null,
                    'pending_digest' => null,
                    'pending_created_at' => null,
                ])
                ->run();

            return $affected === 1;
        });
    }

    #[\Override]
    public function verify(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $code,
    ): bool {
        if (!self::validCodeShape($code)) {
            return false;
        }

        return $this->database->transaction(function () use (
            $subjectId,
            $code,
        ): bool {
            $row = $this->row($subjectId);

            if (
                $row === null
                || ($row['active_ciphertext'] ?? null) === null
                || ($row['enabled_at'] ?? null) === null
            ) {
                return false;
            }

            $subject = $subjectId->toString();
            $digits = self::intValue($row, 'active_digits');
            $period = self::intValue($row, 'active_period');
            $digest = self::stringValue($row, 'active_digest');

            if (!self::validCode($code, $digits)) {
                return false;
            }

            $lastUsedStep = self::nullableIntValue(
                $row,
                'last_used_step',
            );
            $secret = $this->keyring->decrypt(
                self::stringValue($row, 'active_key_id'),
                self::stringValue($row, 'active_nonce'),
                self::stringValue($row, 'active_ciphertext'),
                $subject,
            );

            try {
                $step = $this->matchingStep(
                    $secret,
                    $digits,
                    $period,
                    $digest,
                    $code,
                    $lastUsedStep,
                );
            } finally {
                sodium_memzero($secret);
            }

            if ($step === null) {
                return false;
            }

            $update = $this->database->update($this->table)
                ->where('subject_uuid', $subject)
                ->where('enabled_at', '!=', null);

            if ($lastUsedStep === null) {
                $update->where('last_used_step', null);
            } else {
                $update->where('last_used_step', $lastUsedStep);
            }

            return $update
                ->values(['last_used_step' => $step])
                ->run() === 1;
        });
    }

    #[\Override]
    public function find(UuidInterface $subjectId): ?TotpCredential
    {
        $row = $this->row($subjectId);

        if (
            $row === null
            || ($row['active_ciphertext'] ?? null) === null
            || ($row['enabled_at'] ?? null) === null
        ) {
            return null;
        }

        return new TotpCredential(
            subjectId: $subjectId,
            digits: self::intValue($row, 'active_digits'),
            period: self::intValue($row, 'active_period'),
            digest: self::stringValue($row, 'active_digest'),
            createdAt: $this->date(
                self::stringValue($row, 'created_at'),
            ),
            enabledAt: $this->date(
                self::stringValue($row, 'enabled_at'),
            ),
            lastUsedStep: self::nullableIntValue(
                $row,
                'last_used_step',
            ),
        );
    }

    #[\Override]
    public function disable(UuidInterface $subjectId): void
    {
        $this->database->delete($this->table)
            ->where('subject_uuid', $subjectId->toString())
            ->run();
    }

    private function clearPending(
        string $subjectId,
        #[\SensitiveParameter]
        string $pendingCiphertext,
    ): void {
        $this->database->update($this->table)
            ->where('subject_uuid', $subjectId)
            ->where('pending_ciphertext', $pendingCiphertext)
            ->values([
                'pending_key_id' => null,
                'pending_nonce' => null,
                'pending_ciphertext' => null,
                'pending_digits' => null,
                'pending_period' => null,
                'pending_digest' => null,
                'pending_created_at' => null,
            ])
            ->run();
    }

    private function matchingStep(
        #[\SensitiveParameter]
        string $secret,
        int $digits,
        int $period,
        string $digest,
        #[\SensitiveParameter]
        string $code,
        ?int $lastUsedStep,
    ): ?int {
        /** @var non-empty-string $secret */
        /** @var non-empty-string $digest */
        /** @var non-empty-string $code */
        $otp = TOTP::createFromSecret($secret, $this->clock)
            ->withDigits($digits)
            ->withPeriod($period)
            ->withDigest($digest);
        $currentStep = intdiv(
            $this->clock->now()->getTimestamp(),
            $period,
        );

        for ($offset = -$this->window; $offset <= $this->window; ++$offset) {
            $step = $currentStep + $offset;

            if (
                $step < 0
                || ($lastUsedStep !== null && $step <= $lastUsedStep)
            ) {
                continue;
            }

            $timestamp = $step * $period;
            /** @var int<0, max> $timestamp */
            if ($otp->verify($code, $timestamp, 0)) {
                return $step;
            }
        }

        return null;
    }

    /** @return array<array-key, mixed>|null */
    private function row(UuidInterface $subjectId): ?array
    {
        $row = $this->database->select()
            ->from($this->table)
            ->where('subject_uuid', $subjectId->toString())
            ->run()
            ->fetch();

        return is_array($row) ? $row : null;
    }

    private function now(): DateTimeImmutable
    {
        return $this->clock->now()->setTimezone(new DateTimeZone('UTC'));
    }

    private function format(DateTimeImmutable $date): string
    {
        return $date->setTimezone(new DateTimeZone('UTC'))
            ->format(self::DATE_FORMAT);
    }

    private function date(string $value): DateTimeImmutable
    {
        $timezone = new DateTimeZone('UTC');

        foreach (['!Y-m-d H:i:s.u', '!Y-m-d H:i:s'] as $format) {
            $date = DateTimeImmutable::createFromFormat(
                $format,
                $value,
                $timezone,
            );

            if ($date instanceof DateTimeImmutable) {
                return $date;
            }
        }

        throw new \UnexpectedValueException(
            'Persisted TOTP timestamp is invalid.',
        );
    }

    private static function validCodeShape(string $code): bool
    {
        return preg_match('/\A[0-9]{6,8}\z/D', $code) === 1;
    }

    private static function validCode(string $code, int $digits): bool
    {
        return strlen($code) === $digits
            && preg_match('/\A[0-9]+\z/D', $code) === 1;
    }

    private static function assertLabel(string $value, string $name): void
    {
        if (
            $value === ''
            || strlen($value) > 320
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
        ) {
            throw new \InvalidArgumentException($name . ' is invalid.');
        }
    }

    /** @param array<array-key, mixed> $row */
    private static function stringValue(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        if (!is_string($value) && !is_int($value)) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" is invalid.', $key),
            );
        }

        return (string) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function intValue(array $row, string $key): int
    {
        $value = $row[$key] ?? null;

        if (!is_int($value) && !(is_string($value) && ctype_digit($value))) {
            throw new \UnexpectedValueException(
                sprintf('Database column "%s" must be an integer.', $key),
            );
        }

        return (int) $value;
    }

    /** @param array<array-key, mixed> $row */
    private static function nullableIntValue(
        array $row,
        string $key,
    ): ?int {
        return ($row[$key] ?? null) === null
            ? null
            : self::intValue($row, $key);
    }
}
