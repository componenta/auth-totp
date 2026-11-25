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

    public function testKeyringRetainsValidatedKeyBytesWhenInputReferenceChanges(): void
    {
        $key = str_repeat('k', 32);
        $keyring = new TotpKeyring('current', ['current' => &$key]);
        $before = $keyring->encrypt('BEFORE', 'subject-a');

        $key = str_repeat('r', 32);

        self::assertSame(
            'BEFORE',
            $keyring->decrypt(
                $before['keyId'],
                $before['nonce'],
                $before['ciphertext'],
                'subject-a',
            ),
        );

        $after = $keyring->encrypt('AFTER', 'subject-a');
        $original = new TotpKeyring('current', ['current' => str_repeat('k', 32)]);
        self::assertSame(
            'AFTER',
            $original->decrypt(
                $after['keyId'],
                $after['nonce'],
                $after['ciphertext'],
                'subject-a',
            ),
        );
    }

    public function testNewKeyringCanRotateEncryptionWhileRetainingDecryptionKey(): void
    {
        $oldKey = str_repeat('k', 32);
        $old = new TotpKeyring('old', ['old' => $oldKey]);
        $encrypted = $old->encrypt('SECRET', 'subject-a');

        $rotated = new TotpKeyring('new', [
            'old' => $oldKey,
            'new' => str_repeat('r', 32),
        ]);

        self::assertSame(
            'SECRET',
            $rotated->decrypt(
                $encrypted['keyId'],
                $encrypted['nonce'],
                $encrypted['ciphertext'],
                'subject-a',
            ),
        );
        self::assertSame('new', $rotated->encrypt('SECRET', 'subject-a')['keyId']);
    }
}
