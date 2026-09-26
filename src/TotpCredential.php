<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Identity\UuidInterface;
use DateTimeImmutable;

final readonly class TotpCredential
{
    public bool $enabled;

    public function __construct(
        public UuidInterface $subjectId,
        public int $digits,
        public int $period,
        public string $digest,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $enabledAt,
        public ?int $lastUsedStep,
    ) {
        if (
            $this->digits < 6
            || $this->digits > 8
            || $this->period < 15
            || $this->period > 120
            || !in_array(
                strtolower($this->digest),
                ['sha1', 'sha256', 'sha512'],
                true,
            )
        ) {
            throw new \InvalidArgumentException(
                'TOTP credential parameters are invalid.',
            );
        }

        if ($this->lastUsedStep !== null && $this->lastUsedStep < 0) {
            throw new \InvalidArgumentException(
                'TOTP last-used step is invalid.',
            );
        }

        $this->enabled = $this->enabledAt !== null;
    }
}
