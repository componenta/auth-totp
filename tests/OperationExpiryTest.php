<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\DatabaseTotpManager;
use Componenta\Auth\Totp\TotpKeyring;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\Uuid;
use Cycle\Database\Config\SQLiteDriverConfig;
use Cycle\Database\Database;
use Cycle\Database\Driver\SQLite\SQLiteDriver;
use OTPHP\TOTP;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

final class OperationExpiryTest extends TestCase
{
    /** @return iterable<string, array{int, bool, bool}> */
    public static function enrollmentDelays(): iterable
    {
        foreach ([false, true] as $hasActiveCredential) {
            $prefix = $hasActiveCredential ? 'replacement' : 'first enrollment';
            yield $prefix . ' before expiry' => [0, true, $hasActiveCredential];
            yield $prefix . ' at expiry' => [1, false, $hasActiveCredential];
            yield $prefix . ' after expiry' => [2, false, $hasActiveCredential];
        }
    }

    #[DataProvider('enrollmentDelays')]
    public function testEnrollmentCannotActivateAfterItsPendingSecretExpires(
        int $delay,
        bool $accepted,
        bool $hasActiveCredential,
    ): void {
        [$database, $driver, $clock] = self::database();
        $manager = self::manager($database, $clock);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $activeOtp = null;

        if ($hasActiveCredential) {
            $active = $manager->beginEnrollment($subject, 'user', 'Example');
            $activeOtp = TOTP::createFromSecret($active->secret, $clock);
            self::assertTrue($manager->confirmEnrollment($subject, $activeOtp->now()));
        }

        $pending = $manager->beginEnrollment($subject, 'user', 'Example');
        $pendingOtp = TOTP::createFromSecret($pending->secret, $clock);
        $clock->advance('+59 seconds');
        $driver->beforeNextWrite = static fn() => $clock->advance(sprintf('+%d seconds', $delay));

        $confirmed = $manager->confirmEnrollment($subject, $pendingOtp->now());

        self::assertSame($accepted, $confirmed);
        self::assertNull($driver->beforeNextWrite, 'The activation must cross the delayed write boundary.');
        self::assertSame($accepted || $hasActiveCredential, $manager->find($subject) !== null);

        if (!$accepted && $activeOtp !== null) {
            self::assertTrue($manager->verify($subject, $activeOtp->now()),
                'Rejecting an expired replacement must preserve the existing factor.');
        }

        if (!$accepted) {
            self::assertFalse($manager->confirmEnrollment($subject, $pendingOtp->now()));
        }
    }

    public function testExpiredEnrollmentDoesNotRollBackItsCallersTransaction(): void
    {
        [$database, $driver, $clock] = self::database();
        $manager = self::manager($database, $clock);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $pending = $manager->beginEnrollment($subject, 'user', 'Example');
        $pendingOtp = TOTP::createFromSecret($pending->secret, $clock);
        $clock->advance('+59 seconds');
        $other = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abd');

        $database->transaction(static function () use ($manager, $subject, $pendingOtp, $driver, $clock, $other): void {
            $otherEnrollment = $manager->beginEnrollment($other, 'other', 'Example');
            self::assertTrue($manager->confirmEnrollment(
                $other,
                TOTP::createFromSecret($otherEnrollment->secret, $clock)->now(),
            ));
            $driver->beforeNextWrite = static fn() => $clock->advance('+1 second');

            self::assertFalse($manager->confirmEnrollment($subject, $pendingOtp->now()));
            self::assertNotNull($manager->find($other));
        });

        self::assertNull($manager->find($subject));
        self::assertNotNull($manager->find($other));
    }

    /** @return iterable<string, array{int, bool}> */
    public static function activationDelays(): iterable
    {
        yield 'code remains in its accepted step' => [29, true];
        yield 'code reaches its next step' => [30, false];
        yield 'code passes its accepted step' => [31, false];
    }

    #[DataProvider('activationDelays')]
    public function testEnrollmentAlsoRequiresAValidCodeWhenActivationFinishes(int $delay, bool $accepted): void
    {
        [$database, $driver, $clock] = self::database();
        $manager = self::manager($database, $clock, window: 0);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $pending = $manager->beginEnrollment($subject, 'user', 'Example');
        $otp = TOTP::createFromSecret($pending->secret, $clock);
        $driver->beforeNextWrite = static fn() => $clock->advance(sprintf('+%d seconds', $delay));

        self::assertSame($accepted, $manager->confirmEnrollment($subject, $otp->now()));
        self::assertNull($driver->beforeNextWrite);
        self::assertSame($accepted, $manager->find($subject) !== null);
    }

    /** @return iterable<string, array{string, int, int, bool}> */
    public static function verificationDelays(): iterable
    {
        foreach ([0, 1, 2] as $window) {
            foreach (['UPDATE', 'Commit transaction'] as $boundary) {
                $lifetime = ($window + 1) * 30;
                $prefix = sprintf('window %d %s', $window, $boundary);
                yield $prefix . ' before expiry' => [$boundary, $window, $lifetime - 1, true];
                yield $prefix . ' at expiry' => [$boundary, $window, $lifetime, false];
                yield $prefix . ' after expiry' => [$boundary, $window, $lifetime + 1, false];
            }
        }
    }

    #[DataProvider('verificationDelays')]
    public function testVerificationRejectsAStepThatExpiresDuringItsClaim(
        string $boundary,
        int $window,
        int $delay,
        bool $accepted,
    ): void {
        [$database, $driver, $clock] = self::database();
        $manager = self::manager($database, $clock, $window);
        $subject = Uuid::fromString('018f6d5d-3f7a-7a9b-8c2f-123456789abc');
        $enrollment = $manager->beginEnrollment($subject, 'user', 'Example');
        $otp = TOTP::createFromSecret($enrollment->secret, $clock);
        self::assertTrue($manager->confirmEnrollment($subject, $otp->now()));
        $clock->advance('+30 seconds');
        $claimedStep = intdiv($clock->now()->getTimestamp(), 30);
        $code = $otp->now();
        $logger = new class($clock, $boundary, $delay) extends AbstractLogger {
            public bool $advanced = false;

            public function __construct(
                private FrozenClock $clock,
                private string $boundary,
                private int $delay,
            ) {}

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                if (!$this->advanced && str_starts_with((string) $message, $this->boundary)) {
                    $this->advanced = true;
                    $this->clock->advance(sprintf('+%d seconds', $this->delay));
                }
            }
        };
        $driver->setLogger($logger);

        self::assertSame($accepted, $manager->verify($subject, $code));
        self::assertTrue($logger->advanced, 'The claim must cross the delayed database boundary.');
        self::assertSame($claimedStep, $manager->find($subject)?->lastUsedStep,
            'A completed claim remains consumed even when its proof has expired.');
        self::assertFalse($manager->verify($subject, $code));
    }

    /** @return array{Database, TotpDelayedWriteDriver, FrozenClock} */
    private static function database(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $driver = TotpDelayedWriteDriver::create(new SQLiteDriverConfig());
        $database = new Database('totp-expiry', '', $driver);
        $schema = file_get_contents(dirname(__DIR__) . '/resources/schema/sqlite.sql');

        if (!is_string($schema)) {
            throw new \RuntimeException('TOTP schema is unavailable.');
        }

        foreach (array_filter(array_map('trim', explode(';', $schema))) as $sql) {
            $database->execute($sql);
        }

        return [$database, $driver, new FrozenClock('2030-01-01T00:00:00Z', 'UTC')];
    }

    private static function manager(Database $database, FrozenClock $clock, int $window = 1): DatabaseTotpManager
    {
        return new DatabaseTotpManager(
            $database,
            $clock,
            new TotpKeyring('test', ['test' => str_repeat('k', 32)]),
            window: $window,
            enrollmentTtlSeconds: 60,
        );
    }
}

/** Simulates waiting for a database write before it executes its SQL. */
final class TotpDelayedWriteDriver extends SQLiteDriver
{
    public ?\Closure $beforeNextWrite = null;

    #[\Override]
    public function execute(string $query, array $parameters = []): int
    {
        if (!str_starts_with(ltrim($query), 'UPDATE')) {
            return parent::execute($query, $parameters);
        }

        $delay = $this->beforeNextWrite;
        $this->beforeNextWrite = null;
        $delay?->__invoke();

        return parent::execute($query, $parameters);
    }
}
