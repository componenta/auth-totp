<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp\Tests;

use Componenta\Auth\AuthenticationAdmission;
use Componenta\Auth\AuthenticationEvidence;
use Componenta\Auth\AuthenticationGuardInterface;
use Componenta\Auth\IdentityProviderInterface;
use Componenta\Auth\Session\AssuranceRequirement;
use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthSessionRegistryInterface;
use Componenta\Auth\Session\Http\Csrf\AuthSessionCsrfTokenManager;
use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Clock\FrozenClock;
use Componenta\Identity\IdentityInterface;
use Componenta\Identity\UuidFactory;
use Componenta\Identity\UuidInterface;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use Componenta\Auth\Totp\DatabaseTotpManager;
use Componenta\Auth\Totp\TotpKeyring;
use Componenta\Auth\Totp\TotpEnrollment;
use Componenta\Auth\Totp\TotpEnrollmentConfirmHandler;
use Componenta\Auth\Totp\TotpEnrollmentStartHandler;
use Componenta\Auth\Totp\TotpManagerInterface;
use Componenta\Auth\Totp\Tests\Support\SqliteDatabaseFixture;
use OTPHP\TOTP;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamInterface;

final class EnrollmentAuthorizationTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function responseStreams(): iterable
    {
        foreach (['complete', 'partial', 'stalled', 'throwing'] as $mode) {
            yield $mode => [$mode];
        }
    }

    #[DataProvider('responseStreams')]
    public function testEnrollmentResponseIsCompleteOrFails(string $mode): void
    {
        [$gate, $request] = $this->context('allowed');
        $enrollment = new TotpEnrollment('synthetic-secret', 'otpauth://totp/Example?secret=synthetic');
        $totp = $this->createStub(TotpManagerInterface::class);
        $totp->method('beginEnrollment')->willReturn($enrollment);
        $sink = new class {
            public string $body = '';
            public int $calls = 0;
        };
        $failure = new \RuntimeException('Synthetic enrollment response stream failed.');
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('write')->willReturnCallback(
            static function (string $bytes) use ($mode, $sink, $failure): int {
                if (++$sink->calls > 1) {
                    if ($mode === 'stalled') {
                        return 0;
                    }
                    if ($mode === 'throwing') {
                        throw $failure;
                    }
                }
                $written = $mode === 'complete' ? strlen($bytes) : min(7, strlen($bytes));
                $sink->body .= substr($bytes, 0, $written);

                return $written;
            },
        );
        $stream->method('__toString')->willReturnCallback(static fn(): string => $sink->body);
        $responses = $this->createStub(ResponseFactoryInterface::class);
        $responses->method('createResponse')->willReturn(new Response(200, [], $stream));
        $handler = new TotpEnrollmentStartHandler($totp, $responses, $gate, 'Example');
        $request = $request->withParsedBody(['label' => 'User']);

        if (in_array($mode, ['stalled', 'throwing'], true)) {
            $observed = null;
            try {
                $handler->handle($request);
            } catch (\RuntimeException $exception) {
                $observed = $exception;
            }

            self::assertInstanceOf(\RuntimeException::class, $observed,
                'A truncated enrollment response must not be returned as success.');
            if ($mode === 'throwing') {
                self::assertSame($failure, $observed);
            }
            self::assertSame(2, $sink->calls);

            return;
        }

        $response = $handler->handle($request);

        self::assertSame(200, $response->getStatusCode());
        self::assertJson((string) $response->getBody());
        self::assertSame([
            'secret' => $enrollment->secret,
            'provisioning_uri' => $enrollment->provisioningUri,
        ], json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR));
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertStringContainsString('no-store', $response->getHeaderLine('Cache-Control'));
    }

    #[DataProvider('requests')]
    public function testGateRunsBeforeFactorMutation(bool $start, string $case, int $status): void
    {
        [$gate, $request, $responses, $identity] = $this->context($case);
        $totp = $this->createMock(TotpManagerInterface::class);
        $method = $start ? 'beginEnrollment' : 'confirmEnrollment';
        $totp->expects($case === 'allowed' ? self::once() : self::never())->method($method)
            ->willReturn($start ? new TotpEnrollment('synthetic-secret', 'otpauth://totp/test') : true);
        $handler = $start ? new TotpEnrollmentStartHandler($totp, $responses, $gate, 'Example') : new TotpEnrollmentConfirmHandler($totp, $responses, $gate);
        $response = $handler->handle($request->withParsedBody(['label' => 'User', 'code' => '123456']));
        self::assertSame($status, $response->getStatusCode());
        self::assertStringContainsString('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public static function requests(): iterable
    {
        foreach ([true, false] as $start) {
            yield [$start, 'get', 405];
            yield [$start, 'no-csrf', 403];
            yield [$start, 'missing-origin', 403];
            yield [$start, 'stale', 403];
            yield [$start, 'allowed', $start ? 200 : 204];
        }
    }

    public function testEnrollmentValidationFailureReturnsAnUnprocessableResponse(): void
    {
        [$gate, $request, $responses] = $this->context('allowed');
        $totp = new DatabaseTotpManager(
            $this->createStub(\Cycle\Database\DatabaseInterface::class),
            new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC'),
            new TotpKeyring('current', ['current' => str_repeat('k', 32)]),
        );
        $handler = new TotpEnrollmentStartHandler($totp, $responses, $gate, 'Example');

        $response = $handler->handle($request->withParsedBody([
            'label' => str_repeat('x', 321),
        ]));

        self::assertSame(422, $response->getStatusCode());
    }

    public function testUnexpectedEnrollmentFailureIsNotReportedAsInvalidInput(): void
    {
        [$gate, $request, $responses] = $this->context('allowed');
        $totp = $this->createStub(TotpManagerInterface::class);
        $totp->method('beginEnrollment')->willThrowException(
            new \RuntimeException('Storage is unavailable.'),
        );
        $handler = new TotpEnrollmentStartHandler($totp, $responses, $gate, 'Example');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Storage is unavailable.');

        $handler->handle($request->withParsedBody(['label' => 'User']));
    }

    /** @return iterable<string, array{string}> */
    public static function labelsWithIssuer(): iterable
    {
        yield 'literal separator' => ['Other:User'];
        yield 'encoded separator' => ['Other%3AUser'];
    }

    #[DataProvider('labelsWithIssuer')]
    public function testInvalidProvisioningLabelDoesNotReplacePendingEnrollment(string $label): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        [$gate, $request, $responses, $identity] = $this->context('allowed');
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $totp = new DatabaseTotpManager(
            SqliteDatabaseFixture::create(),
            $clock,
            new TotpKeyring('current', ['current' => str_repeat('k', 32)]),
        );
        $pending = $totp->beginEnrollment($identity->uuid, 'User', 'Example');
        $handler = new TotpEnrollmentStartHandler($totp, $responses, $gate, 'Example');

        $response = $handler->handle($request->withParsedBody(['label' => $label]));

        self::assertSame(422, $response->getStatusCode());
        $code = TOTP::createFromSecret($pending->secret, $clock)->now();
        self::assertTrue(
            $totp->confirmEnrollment($identity->uuid, $code),
            'Rejecting a new label must preserve the previously issued enrollment.',
        );
    }

    private function context(string $case): array
    {
        $uuids = new UuidFactory();
        $identity = new readonly class($uuids->generate()) implements IdentityInterface {
            public function __construct(public UuidInterface $uuid) {}
        };
        $clock = new FrozenClock('2030-01-01T00:00:00+00:00', 'UTC');
        $at = $clock->now()->modify($case === 'stale' ? '-600 seconds' : '-60 seconds');
        $session = new AuthSession($uuids->generate(), $identity->uuid, new AuthenticationEvidence(['password']), 1, $at, null, $at, $at->modify('+1 hour'), $at->modify('+8 hours'));
        $registry = $this->createStub(AuthSessionRegistryInterface::class);
        $registry->method('find')->willReturn($session);
        $provider = $this->createStub(IdentityProviderInterface::class);
        $provider->method('findByUuid')->willReturn($identity);
        $guard = $this->createStub(AuthenticationGuardInterface::class);
        $guard->method('check')->willReturn(null);
        $responses = new Psr17Factory();
        $key = str_repeat('k', 32);
        $gate = new FactorManagementGuard($registry, new AuthenticationAdmission($provider, $guard), new AssuranceRequirement(['password'], maxAge: 300), $clock, $responses, $key);
        $request = (new ServerRequest($case === 'get' ? 'GET' : 'POST', 'https://example.test/factors'))
            ->withAttribute(IdentityInterface::class, $identity)
            ->withAttribute(AuthSession::class, $session);
        if ($case !== 'missing-origin') {
            $request = $request->withHeader('Origin', 'https://example.test');
        }
        if ($case !== 'no-csrf') {
            $request = $request->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($session, $key))->generate());
        }
        return [$gate, $request, $responses, $identity];
    }
}
