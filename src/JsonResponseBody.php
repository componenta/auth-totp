<?php

declare(strict_types=1);

namespace Componenta\Auth\Totp;

use Psr\Http\Message\ResponseInterface;

/** @internal Writes the complete JSON body before a response is returned. */
final class JsonResponseBody
{
    private function __construct() {}

    /** @param array<string, mixed> $payload */
    public static function write(
        #[\SensitiveParameter]
        ResponseInterface $response,
        #[\SensitiveParameter]
        array $payload,
    ): void {
        $json = json_encode($payload, JSON_THROW_ON_ERROR);
        $stream = $response->getBody();
        $length = strlen($json);
        $offset = 0;

        while ($offset < $length) {
            $written = $stream->write(substr($json, $offset));

            if ($written <= 0 || $written > $length - $offset) {
                throw new \RuntimeException('Could not write a complete JSON response.');
            }

            $offset += $written;
        }
    }
}
