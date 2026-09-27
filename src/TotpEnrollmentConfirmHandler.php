<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class TotpEnrollmentConfirmHandler implements RequestHandlerInterface
{
    public function __construct(
        private TotpManagerInterface $totp,
        private ResponseFactoryInterface $responses,
        private FactorManagementGuard $guard,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        if (($denial = $this->guard->check($request)) !== null) {
            return $denial;
        }

        $identity = $request->getAttribute(IdentityInterface::class);
        $body = $request->getParsedBody();
        $code = is_array($body) ? ($body['code'] ?? null) : null;

        if (
            !$identity instanceof IdentityInterface
            || !is_string($code)
            || !$this->totp->confirmEnrollment($identity->uuid, $code)
        ) {
            return $this->responses->createResponse(400)
                ->withHeader('Cache-Control', 'no-store')
                ->withHeader('Pragma', 'no-cache');
        }

        return $this->responses->createResponse(204)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
