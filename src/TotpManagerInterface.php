<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Identity\UuidInterface;

interface TotpManagerInterface
{
    public function beginEnrollment(
        UuidInterface $subjectId,
        string $label,
        string $issuer,
    ): TotpEnrollment;

    public function confirmEnrollment(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $code,
    ): bool;

    public function verify(
        UuidInterface $subjectId,
        #[\SensitiveParameter]
        string $code,
    ): bool;

    public function find(UuidInterface $subjectId): ?TotpCredential;

    public function disable(UuidInterface $subjectId): void;
}
