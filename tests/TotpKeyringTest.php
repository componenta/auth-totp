<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\TotpKeyring;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TotpKeyringTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function keyIdentifiers(): iterable
    {
        yield 'zero' => ['0'];
        yield 'decimal identifier' => ['2026'];
        yield 'leading zero remains significant' => ['01'];
        yield 'named identifier' => ['current-key'];
    }

    #[DataProvider('keyIdentifiers')]
    public function testAcceptedKeyIdentifierCanEncryptAndDecrypt(string $id): void
    {
        $keyring = new TotpKeyring($id, [$id => str_repeat('k', 32)]);

        $encrypted = $keyring->encrypt('SECRET', 'subject-a');

        self::assertSame($id, $encrypted['keyId']);
        self::assertSame(
            'SECRET',
            $keyring->decrypt(
                $encrypted['keyId'],
                $encrypted['nonce'],
                $encrypted['ciphertext'],
                'subject-a',
            ),
        );
    }

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
