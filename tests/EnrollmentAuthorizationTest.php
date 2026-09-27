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
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

use Componenta\Auth\Totp\TotpEnrollment;
use Componenta\Auth\Totp\TotpEnrollmentConfirmHandler;
use Componenta\Auth\Totp\TotpEnrollmentStartHandler;
use Componenta\Auth\Totp\TotpManagerInterface;

final class EnrollmentAuthorizationTest extends TestCase
{
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
            yield [$start, 'stale', 403];
            yield [$start, 'allowed', $start ? 200 : 204];
        }
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
        if ($case !== 'no-csrf') {
            $request = $request->withHeader('X-CSRF-Token', (new AuthSessionCsrfTokenManager($session, $key))->generate());
        }
        return [$gate, $request, $responses, $identity];
    }
}
