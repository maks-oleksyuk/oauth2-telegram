<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Exception;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;

class TelegramIdentityProviderException extends IdentityProviderException
{
    public function __construct(string $message, int $code = 0, mixed $response = '', ?\Throwable $previous = null)
    {
        $this->response = $response;
        \Exception::__construct($message, $code, $previous);
    }

    /**
     * Telegram answers token errors with HTTP 200 and `{"error": "invalid_grant"}`, no `error_description`.
     *
     * @param array<mixed>|string $data Parsed response body
     */
    public static function fromResponse(ResponseInterface $response, array|string $data): self
    {
        $message = \is_array($data) ? ($data['error_description'] ?? $data['error'] ?? null) : null;

        return new self(\is_string($message) && '' !== $message ? $message : $response->getReasonPhrase(), $response->getStatusCode(), $data);
    }

    /**
     * Wraps a firebase/php-jwt failure (ExpiredException, SignatureInvalidException, …).
     */
    public static function invalidIdToken(\Throwable $previous): self
    {
        return new self('Invalid ID token: '.$previous->getMessage(), 0, '', $previous);
    }
}
