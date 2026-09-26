<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

final readonly class TotpEnrollment implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter]
        public string $secret,
        #[\SensitiveParameter]
        public string $provisioningUri,
    ) {
        if ($this->secret === '' || $this->provisioningUri === '') {
            throw new \InvalidArgumentException(
                'TOTP enrollment is incomplete.',
            );
        }
    }

    /** @return array{secret: string, provisioningUri: string} */
    public function __debugInfo(): array
    {
        return [
            'secret' => '[REDACTED]',
            'provisioningUri' => '[REDACTED]',
        ];
    }

    /** @return array{secret: string, provisioningUri: string} */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }
}
