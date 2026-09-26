<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Auth\AuthenticationEvidence;

final class TotpEvidence
{
    private function __construct() {}

    public static function create(): AuthenticationEvidence
    {
        return new AuthenticationEvidence(
            methods: ['totp'],
            capabilities: ['possession'],
        );
    }
}
