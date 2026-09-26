<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\DatabaseTotpManager;
use Componenta\Auth\Totp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Totp\TotpKeyring;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;

final class DatabaseTotpManagerTest extends TestCase
{
    public function testEnrollmentStoresOnlyEncryptedSecretAndRequiresConfirmation(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = self::manager($database, $clock);
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );

        $enrollment = $manager->beginEnrollment(
            $subject,
            'user@example.com',
            'Componenta',
        );
        $row = $database->select()
            ->from('auth_totp_credentials')
            ->where('subject_uuid', $subject->toString())
            ->run()
            ->fetch();

        self::assertIsArray($row);
        $serialized = json_encode($row, JSON_THROW_ON_ERROR);
        self::assertStringNotContainsString($enrollment->secret, $serialized);
        self::assertNull($manager->find($subject));

        $otp = TOTP::createFromSecret($enrollment->secret, $clock)
            ->withDigits(6)
            ->withPeriod(30)
            ->withDigest('sha1');

        self::assertTrue(
            $manager->confirmEnrollment($subject, $otp->now()),
        );
        self::assertNotNull($manager->find($subject));
    }

    public function testAcceptedTimeStepCannotBeReplayed(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $manager = self::manager($database, $clock);
        $subject = Uuid::fromString(
            '018f6d5d-3f7a-7a9b-8c2f-123456789abc',
        );
        $enrollment = $manager->beginEnrollment(
            $subject,
            'user@example.com',
            'Componenta',
        );
        $otp = TOTP::createFromSecret($enrollment->secret, $clock)
            ->withDigits(6)
            ->withPeriod(30)
            ->withDigest('sha1');

        self::assertTrue(
            $manager->confirmEnrollment($subject, $otp->now()),
        );

        $clock->advance('+30 seconds');
        $code = $otp->now();

        self::assertTrue($manager->verify($subject, $code));
        self::assertFalse($manager->verify($subject, $code));
    }

    private static function manager(
        \Cycle\Database\DatabaseInterface $database,
        FrozenClock $clock,
    ): DatabaseTotpManager {
        return new DatabaseTotpManager(
            $database,
            $clock,
            new TotpKeyring(
                'k1',
                ['k1' => str_repeat('k', 32)],
            ),
        );
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
