<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Auth\AuthenticationEvidence;

final class TotpEvidence
{
    private function __construct() {}

    public static function augment(
        AuthenticationEvidence $evidence,
    ): AuthenticationEvidence {
        return new AuthenticationEvidence(
            methods: array_values(array_unique([
                ...$evidence->methods,
                'totp',
            ])),
            capabilities: array_values(array_unique([
                ...$evidence->capabilities,
                'possession',
            ])),
        );
    }
}
