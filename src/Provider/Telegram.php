<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Provider;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\OptionProvider\HttpBasicAuthOptionProvider;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use Oleksyuk\OAuth2\Client\Exception\TelegramIdentityProviderException;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Log in with Telegram (OpenID Connect, https://core.telegram.org/bots/telegram-login).
 *
 * Telegram has no UserInfo endpoint: the resource owner is the verified ID token itself.
 *
 * Extra options on top of League's: `algorithm` (ID token signing algorithm picked in @BotFather, default RS256),
 * `pkceMethod` (default S256, null disables PKCE), `jwksCache` (PSR-16 cache for Telegram's signing keys),
 * `jwksCacheTtl` (seconds, default 3600) and `leeway` (allowed clock skew in seconds, default 60).
 */
class Telegram extends AbstractProvider
{
    public const string ISSUER = 'https://oauth.telegram.org';

    /** Signing algorithms Telegram offers in @BotFather. */
    public const array ALGORITHMS = ['RS256', 'ES256', 'ES256K', 'EdDSA'];

    private const string JWKS_CACHE_KEY = 'oauth2_telegram_jwks';

    protected string $algorithm = 'RS256';

    protected ?string $pkceMethod = self::PKCE_METHOD_S256;

    protected ?CacheInterface $jwksCache = null;

    protected int $jwksCacheTtl = 3600;

    protected int $leeway = 60;

    /**
     * @param array<string, mixed> $options
     * @param array<string, mixed> $collaborators
     *
     * @throws \InvalidArgumentException
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

    /**
     * @throws \LogicException
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        throw new \LogicException('Telegram has no UserInfo endpoint, the ID token is the resource owner.');
    }

    /**
     * @throws TelegramIdentityProviderException
     */
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
     * @param  array<mixed>|string  $data
     *
     * @throws TelegramIdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() >= 400 || (\is_array($data) && isset($data['error']))) {
            throw TelegramIdentityProviderException::fromResponse($response, $data);
        }
    }

    /**
     * @return array<mixed>
     *
     * @throws TelegramIdentityProviderException
     */
    protected function fetchResourceOwnerDetails(AccessToken $token): array
    {
        $idToken = $token->getValues()['id_token'] ?? null;
        if (!\is_string($idToken) || '' === $idToken) {
            throw new TelegramIdentityProviderException('Telegram did not return an ID token.', 0, '');
        }

        $claims = $this->verify($idToken);

        if (self::ISSUER !== ($claims['iss'] ?? null)) {
            throw new TelegramIdentityProviderException('Unexpected ID token issuer.', 0, $claims);
        }

        $audiences = array_map(static fn (mixed $aud): string => \is_scalar($aud) ? (string) $aud : '', (array) ($claims['aud'] ?? []));
        if (!\in_array($this->clientId, $audiences, true)) {
            throw new TelegramIdentityProviderException('ID token audience does not match the client id.', 0, $claims);
        }

        $sub = $claims['sub'] ?? null;
        if ((!\is_string($sub) && !\is_int($sub)) || '' === $sub) {
            throw new TelegramIdentityProviderException('ID token has no subject.', 0, $claims);
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
     *
     * @throws TelegramIdentityProviderException
     */
    private function verify(string $idToken): array
    {
        $cached = $this->jwksCache?->get(self::JWKS_CACHE_KEY);
        if (\is_array($cached)) {
            try {
                return $this->decode($idToken, $cached);
            } catch (TelegramIdentityProviderException) {
                // Telegram may have rotated its keys: retry once with a fresh set.
            }
        }

        return $this->decode($idToken, $this->fetchJwks());
    }

    /**
     * @return array<mixed>
     *
     * @throws TelegramIdentityProviderException
     */
    private function fetchJwks(): array
    {
        $jwks = $this->getParsedResponse($this->getRequest(self::METHOD_GET, self::ISSUER.'/.well-known/jwks.json'));
        if (!\is_array($jwks)) {
            throw new TelegramIdentityProviderException('Telegram returned an invalid JWKS.', 0, $jwks);
        }

        $this->jwksCache?->set(self::JWKS_CACHE_KEY, $jwks, $this->jwksCacheTtl);

        return $jwks;
    }

    /**
     * Verifies the signature and exp/nbf/iat.
     *
     * @param  array<mixed>  $jwks
     *
     * @return array<mixed>
     *
     * @throws TelegramIdentityProviderException
     */
    private function decode(string $idToken, array $jwks): array
    {
        // php-jwt only has a global leeway: set it for this call and restore it.
        $leeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;

        try {
            return (array) JWT::decode($idToken, JWK::parseKeySet($jwks, $this->algorithm));
        } catch (\Exception $exception) {
            throw TelegramIdentityProviderException::invalidIdToken($exception);
        } finally {
            JWT::$leeway = $leeway;
        }
    }
}
