<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\TotpKeyring;
use PHPUnit\Framework\TestCase;

final class TotpKeyringTest extends TestCase
{
    public function testEncryptionIsSubjectBound(): void
    {
        $keyring = new TotpKeyring(
            'k1',
            ['k1' => str_repeat('k', 32)],
        );
        $encrypted = $keyring->encrypt('SECRET', 'subject-a');

        self::assertSame(
            'SECRET',
            $keyring->decrypt(
                $encrypted['keyId'],
                $encrypted['nonce'],
                $encrypted['ciphertext'],
                'subject-a',
            ),
        );

        $this->expectException(\UnexpectedValueException::class);

        $keyring->decrypt(
            $encrypted['keyId'],
            $encrypted['nonce'],
            $encrypted['ciphertext'],
            'subject-b',
        );
    }
}
