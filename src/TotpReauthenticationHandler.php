<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Auth\Session\AuthSession;
use Componenta\Auth\Session\AuthenticatedSessionIssuer;
use Componenta\Auth\Session\Http\AuthSessionGrantPublisher;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class TotpReauthenticationHandler implements
    RequestHandlerInterface
{
    public function __construct(
        private TotpManagerInterface $totp,
        private AuthenticatedSessionIssuer $sessionIssuer,
        private AuthSessionGrantPublisher $publisher,
        private ResponseFactoryInterface $responses,
    ) {}

    #[\Override]
    public function handle(
        #[\SensitiveParameter]
        ServerRequestInterface $request,
    ): ResponseInterface {
        $identity = $request->getAttribute(IdentityInterface::class);
        $session = $request->getAttribute(AuthSession::class);
        $body = $request->getParsedBody();
        $code = is_array($body) ? ($body['code'] ?? null) : null;

        if (
            !$identity instanceof IdentityInterface
            || !$session instanceof AuthSession
            || !$identity->uuid->equals($session->subjectId)
            || !is_string($code)
        ) {
            return $this->denied();
        }

        // Allocate the response before consuming the one-time code.
        $response = $this->responses->createResponse(204);

        if (!$this->totp->verify($identity->uuid, $code)) {
            return $this->denied();
        }

        $grant = $this->sessionIssuer->reauthenticate(
            $session,
            $identity,
            TotpEvidence::create(),
        );

        return $this->publisher->publish(
            $request,
            $response,
            $grant,
        );
    }

    private function denied(): ResponseInterface
    {
        return $this->responses->createResponse(401)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
