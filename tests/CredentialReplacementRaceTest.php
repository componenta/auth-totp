<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\DatabaseTotpManager;
use Componenta\Auth\Totp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Totp\TotpKeyring;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\Database;
use Cycle\Database\DatabaseInterface;
use OTPHP\TOTP;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

final class CredentialReplacementRaceTest extends TestCase
{
    public function testVerificationCannotCommitAgainstAReplacementSecretWithTheSameCounter(): void
    {
        self::requireSqlite();
        $database = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $keyring = new TotpKeyring('test', ['test' => str_repeat('k', 32)]);
        $manager = new DatabaseTotpManager($database, $clock, $keyring);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $first = $manager->beginEnrollment($subject, 'user', 'Example');
        $firstOtp = TOTP::createFromSecret($first->secret, $clock);
        self::assertTrue($manager->confirmEnrollment($subject, $firstOtp->now()));
        $replacement = $manager->beginEnrollment($subject, 'user', 'Example');
        $replacementCode = TOTP::createFromSecret($replacement->secret, $clock)->now();
        $staleCode = $firstOtp->at($clock->now()->getTimestamp() + 30);

        // Switch factors after verify() has read/decrypted the old row but
        // before its compare-and-swap. Both enrollments share a time step.
        $interleavedClock = new class($clock, static function () use ($manager, $subject, $replacementCode): void {
            self::assertTrue($manager->confirmEnrollment($subject, $replacementCode));
        }) implements ClockInterface {
            public function __construct(private ClockInterface $clock, private ?\Closure $beforeRead) {}
            public function now(): \DateTimeImmutable
            {
                $action = $this->beforeRead;
                $this->beforeRead = null;
                $action?->__invoke();
                return $this->clock->now();
            }
        };
        $racing = new DatabaseTotpManager($database, $interleavedClock, $keyring);

        self::assertFalse($racing->verify($subject, $staleCode));
        $clock->advance('+30 seconds');
        self::assertTrue($manager->verify($subject, TOTP::createFromSecret($replacement->secret, $clock)->now()));
    }

    public function testReadsDoNotReportDisabledFactorFromLaggingReplica(): void
    {
        self::requireSqlite();
        $primary = SqliteDatabaseFixture::create();
        $replica = SqliteDatabaseFixture::create();
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $keyring = new TotpKeyring('test', ['test' => str_repeat('k', 32)]);
        $manager = new DatabaseTotpManager($primary, $clock, $keyring);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $enrollment = $manager->beginEnrollment($subject, 'user', 'Example');
        self::assertTrue($manager->confirmEnrollment($subject, TOTP::createFromSecret($enrollment->secret, $clock)->now()));
        foreach ($primary->select()->from('auth_totp_credentials')->run()->fetchAll() as $row) {
            $replica->insert('auth_totp_credentials')->values($row)->run();
        }
        $manager->disable($subject);
        $split = new Database('split', '', $primary->getDriver(DatabaseInterface::WRITE), $replica->getDriver(DatabaseInterface::READ));
        self::assertNull((new DatabaseTotpManager($split, $clock, $keyring))->find($subject));
    }

    private static function requireSqlite(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
    }
}
