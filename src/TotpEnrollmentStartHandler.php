<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Componenta\Auth\Session\Http\FactorManagementGuard;
use Componenta\Identity\IdentityInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final readonly class TotpEnrollmentStartHandler implements RequestHandlerInterface
{
    public function __construct(
        private TotpManagerInterface $totp,
        private ResponseFactoryInterface $responses,
        private FactorManagementGuard $guard,
        private string $issuer,
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

        if (!$identity instanceof IdentityInterface) {
            return $this->responses->createResponse(401);
        }

        $body = $request->getParsedBody();
        $label = is_array($body) ? ($body['label'] ?? null) : null;

        if (!is_string($label) || $label === '') {
            return $this->responses->createResponse(422);
        }

        try {
            $enrollment = $this->totp->beginEnrollment(
                $identity->uuid,
                $label,
                $this->issuer,
            );
        } catch (\InvalidArgumentException) {
            return $this->responses->createResponse(422);
        }
        $response = $this->responses->createResponse(200);
        JsonResponseBody::write($response, [
            'secret' => $enrollment->secret,
            'provisioning_uri' => $enrollment->provisioningUri,
        ]);

        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache');
    }
}
