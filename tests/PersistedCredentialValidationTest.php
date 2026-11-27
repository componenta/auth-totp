<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\Totp\DatabaseTotpManager;
use Componenta\Auth\Totp\Tests\Support\SqliteDatabaseFixture;
use Componenta\Auth\Totp\TotpEnrollment;
use Componenta\Auth\Totp\TotpKeyring;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Cycle\Database\DatabaseInterface;
use OTPHP\TOTP;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PersistedCredentialValidationTest extends TestCase
{
    private DatabaseInterface $database;
    private FrozenClock $clock;
    private DatabaseTotpManager $manager;
    private UuidInterface $subject;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $this->database = SqliteDatabaseFixture::create();
        $this->clock = new FrozenClock('2030-01-01T00:00:00Z', 'UTC');
        $this->manager = new DatabaseTotpManager(
            $this->database,
            $this->clock,
            new TotpKeyring('current', ['current' => str_repeat('k', 32)]),
            window: 0,
        );
        $this->subject = (new UuidFactory())->generate();
    }

    /** @return iterable<string, array{int, string}> */
    public static function invalidParameters(): iterable
    {
        yield 'period below model minimum' => [14, 'sha1'];
        yield 'period above model maximum' => [121, 'sha1'];
        yield 'digest outside model allowlist' => [30, 'sha224'];
    }

    #[DataProvider('invalidParameters')]
    public function testInvalidPendingParametersPreserveTheExistingFactor(int $period, string $digest): void
    {
        $active = $this->manager->beginEnrollment($this->subject, 'user@example.test', 'Example');
        self::assertTrue($this->manager->confirmEnrollment($this->subject, $this->otp($active)->now()));
        $pending = $this->manager->beginEnrollment($this->subject, 'user@example.test', 'Example');
        // Model persisted/imported metadata; HTTP enrollment only writes defaults.
        $this->database->update('auth_totp_credentials')
            ->where('subject_uuid', $this->subject->toString())
            ->values(['pending_period' => $period, 'pending_digest' => $digest])
            ->run();
        $before = $this->row();
        $code = $this->otp($pending, period: $period, digest: $digest)->now();

        $this->assertInvalidCredential(fn() => $this->manager->confirmEnrollment($this->subject, $code));

        self::assertSame($before, $this->row(), 'Invalid metadata must not activate, clear or replace either factor.');
        $this->clock->advance('+30 seconds');
        self::assertTrue($this->manager->verify($this->subject, $this->otp($active)->now()));
    }

    #[DataProvider('invalidParameters')]
    public function testInvalidActiveParametersCannotBypassTheCredentialModel(int $period, string $digest): void
    {
        $enrollment = $this->manager->beginEnrollment($this->subject, 'user@example.test', 'Example');
        self::assertTrue($this->manager->confirmEnrollment($this->subject, $this->otp($enrollment)->now()));
        $this->database->update('auth_totp_credentials')
            ->where('subject_uuid', $this->subject->toString())
            ->values([
                'active_period' => $period,
                'active_digest' => $digest,
                // Imported credentials may legitimately have no replay history.
                'last_used_step' => null,
            ])
            ->run();
        $before = $this->row();
        $code = $this->otp($enrollment, period: $period, digest: $digest)->now();

        $this->assertInvalidCredential(fn() => $this->manager->find($this->subject));
        $this->assertInvalidCredential(fn() => $this->manager->verify($this->subject, $code));

        self::assertSame($before, $this->row(), 'Rejected persisted parameters must not claim a replay counter.');
    }

    /** @return iterable<string, array{int, int, string}> */
    public static function validParameters(): iterable
    {
        foreach ([15, 120] as $period) {
            foreach (['sha1', 'sha256', 'sha512'] as $digest) {
                yield "$period seconds with $digest" => [6, $period, $digest];
                yield "$period seconds with uppercase $digest" => [6, $period, strtoupper($digest)];
            }
        }

        yield 'seven digits' => [7, 30, 'sha1'];
        yield 'eight digits and mixed-case digest' => [8, 30, 'ShA256'];
    }

    #[DataProvider('validParameters')]
    public function testModelCompatibleParametersCanEnrollAndVerify(int $digits, int $period, string $digest): void
    {
        $enrollment = $this->manager->beginEnrollment($this->subject, 'user@example.test', 'Example');
        $this->database->update('auth_totp_credentials')
            ->where('subject_uuid', $this->subject->toString())
            ->values([
                'pending_digits' => $digits,
                'pending_period' => $period,
                'pending_digest' => $digest,
            ])
            ->run();
        $otp = $this->otp($enrollment, $digits, $period, $digest);

        self::assertTrue($this->manager->confirmEnrollment($this->subject, $otp->now()));
        $credential = $this->manager->find($this->subject);
        self::assertNotNull($credential);
        self::assertSame($digits, $credential->digits);
        self::assertSame($period, $credential->period);
        self::assertSame($digest, $credential->digest);

        $this->clock->advance("+$period seconds");
        $code = $otp->now();
        self::assertTrue($this->manager->verify($this->subject, $code));
        self::assertFalse($this->manager->verify($this->subject, $code));
    }

    private function assertInvalidCredential(callable $operation): void
    {
        $failure = null;

        try {
            $operation();
        } catch (\InvalidArgumentException $exception) {
            $failure = $exception;
        }

        self::assertInstanceOf(
            \InvalidArgumentException::class,
            $failure,
            'Persisted parameters rejected by TotpCredential must not authenticate or activate a factor.',
        );
    }

    private function otp(TotpEnrollment $enrollment, int $digits = 6, int $period = 30, string $digest = 'sha1'): TOTP
    {
        return TOTP::createFromSecret($enrollment->secret, $this->clock)
            ->withDigits($digits)
            ->withPeriod($period)
            ->withDigest($digest);
    }

    /** @return array<string, mixed> */
    private function row(): array
    {
        $row = $this->database->select()->from('auth_totp_credentials')
            ->where('subject_uuid', $this->subject->toString())->run()->fetch();
        self::assertIsArray($row);

        return $row;
    }
}
