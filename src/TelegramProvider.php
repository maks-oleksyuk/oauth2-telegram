<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Log in with Telegram (OpenID Connect, https://core.telegram.org/bots/telegram-login).
 *
 * Telegram has no UserInfo endpoint: the resource owner is the verified ID token itself.
 *
 * Extra options on top of League's: `algorithm` (ID token signing algorithm picked in @BotFather, default RS256),
 * `pkceMethod` (default S256, null disables PKCE), `jwksCache` (PSR-16 cache for Telegram's signing keys)
 * and `jwksCacheTtl` (seconds, default 3600).
 */
class TelegramProvider extends AbstractProvider
{
    use BearerAuthorizationTrait;

    public const string ISSUER = 'https://oauth.telegram.org';

    /** Signing algorithms Telegram offers in @BotFather, all verifiable by firebase/php-jwt. */
    public const array ALGORITHMS = ['RS256', 'ES256', 'ES256K', 'EdDSA'];

    private const string JWKS_CACHE_KEY = 'oauth2_telegram_jwks';

    protected string $algorithm = 'RS256';

    protected ?string $pkceMethod = self::PKCE_METHOD_S256;

    protected ?CacheInterface $jwksCache = null;

    protected int $jwksCacheTtl = 3600;

    /**
     * @param array<string, mixed> $options
     * @param array<string, mixed> $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        // Telegram expects client credentials in the Authorization header of the token request.
        $collaborators += ['optionProvider' => new HttpBasicAuthOptionProvider()];

        parent::__construct($options, $collaborators);

        if (!\in_array($this->algorithm, self::ALGORITHMS, true)) {
            throw new \InvalidArgumentException(\sprintf('Unsupported ID token algorithm "%s", expected one of: %s.', $this->algorithm, implode(', ', self::ALGORITHMS)));
        }
    }

    public function getBaseAuthorizationUrl(): string
    {
        return self::ISSUER.'/auth';
    }

    /**
     * @param array<mixed> $params
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return self::ISSUER.'/token';
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        throw new \LogicException('Telegram has no UserInfo endpoint, the ID token is the resource owner.');
    }

    public function getResourceOwner(AccessToken $token): TelegramResourceOwner
    {
        return $this->createResourceOwner($this->fetchResourceOwnerDetails($token), $token);
    }

    /**
     * @return list<string>
     */
    protected function getDefaultScopes(): array
    {
        return ['openid'];
    }

    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    protected function getPkceMethod(): ?string
    {
        return $this->pkceMethod;
    }

    /**
     * @param array<mixed>|string $data
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() < 400) {
            return;
        }

        // Telegram doesn't document its error body; use the standard OAuth 2.0 fields when present.
        $message = \is_array($data) ? ($data['error_description'] ?? $data['error'] ?? null) : null;

        throw new IdentityProviderException(\is_string($message) && '' !== $message ? $message : $response->getReasonPhrase(), $response->getStatusCode(), $data);
    }

    /**
     * @return array<mixed>
     */
    protected function fetchResourceOwnerDetails(AccessToken $token): array
    {
        $idToken = $token->getValues()['id_token'] ?? null;
        if (!\is_string($idToken) || '' === $idToken) {
            throw new IdentityProviderException('Telegram did not return an ID token.', 0, '');
        }

        $claims = $this->verify($idToken);

        if (self::ISSUER !== ($claims['iss'] ?? null)) {
            throw new IdentityProviderException('Unexpected ID token issuer.', 0, $claims);
        }

        $audiences = array_map(static fn (mixed $aud): string => \is_scalar($aud) ? (string) $aud : '', (array) ($claims['aud'] ?? []));
        if (!\in_array($this->clientId, $audiences, true)) {
            throw new IdentityProviderException('ID token audience does not match the client id.', 0, $claims);
        }

        $sub = $claims['sub'] ?? null;
        if ((!\is_string($sub) && !\is_int($sub)) || '' === $sub) {
            throw new IdentityProviderException('ID token has no subject.', 0, $claims);
        }

        return $claims;
    }

    /**
     * @param array<mixed> $response
     */
    protected function createResourceOwner(array $response, AccessToken $token): TelegramResourceOwner
    {
        return new TelegramResourceOwner($response);
    }

    /**
     * @return array<mixed>
     */
    private function verify(string $idToken): array
    {
        $cached = $this->jwksCache?->get(self::JWKS_CACHE_KEY);
        if (\is_array($cached)) {
            try {
                return $this->decode($idToken, $cached);
            } catch (IdentityProviderException) {
                // Telegram may have rotated its keys: retry once with a fresh set.
            }
        }

        return $this->decode($idToken, $this->fetchJwks());
    }

    /**
     * @return array<mixed>
     */
    private function fetchJwks(): array
    {
        $jwks = $this->getParsedResponse($this->getRequest(self::METHOD_GET, self::ISSUER.'/.well-known/jwks.json'));
        if (!\is_array($jwks)) {
            throw new IdentityProviderException('Telegram returned an invalid JWKS.', 0, $jwks);
        }

        $this->jwksCache?->set(self::JWKS_CACHE_KEY, $jwks, $this->jwksCacheTtl);

        return $jwks;
    }

    /**
     * Verifies the signature and exp/nbf/iat; php-jwt failures are rethrown as IdentityProviderException.
     *
     * @param array<mixed> $jwks
     *
     * @return array<mixed>
     */
    private function decode(string $idToken, array $jwks): array
    {
        try {
            return (array) JWT::decode($idToken, JWK::parseKeySet($jwks, $this->algorithm));
        } catch (\Exception $exception) {
            $invalidToken = new IdentityProviderException('Invalid ID token: '.$exception->getMessage(), 0, '');
            // IdentityProviderException's constructor takes no $previous.
            new \ReflectionProperty(\Exception::class, 'previous')->setValue($invalidToken, $exception);

            throw $invalidToken;
        }
    }
}
