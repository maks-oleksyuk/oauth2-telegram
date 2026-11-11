<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Tests\Provider;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\OptionProvider\PostAuthOptionProvider;
use League\OAuth2\Client\Token\AccessToken;
use Oleksyuk\OAuth2\Client\Exception\TelegramIdentityProviderException;
use Oleksyuk\OAuth2\Client\Provider\Telegram;
use Oleksyuk\OAuth2\Client\Provider\TelegramResourceOwner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\Cache\Psr16Cache;

/**
 * @internal
 */
#[CoversClass(Telegram::class)]
#[CoversClass(TelegramIdentityProviderException::class)]
#[UsesClass(TelegramResourceOwner::class)]
final class TelegramTest extends TestCase
{
    private const string CLIENT_ID = '123456';

    private const string REDIRECT_URI = 'https://example.test/auth/telegram/callback';

    /** @var \ArrayObject<int, array<mixed>> Guzzle history middleware entries. */
    private \ArrayObject $history;

    protected function setUp(): void
    {
        $this->history = new \ArrayObject();
    }

    #[DataProvider('provideResourceOwnerIsTheVerifiedIdTokenCases')]
    public function testResourceOwnerIsTheVerifiedIdToken(string $algorithm): void
    {
        [$signingKey, $jwk] = $this->key($algorithm);

        $owner = $this->provider([$this->jwks($jwk)], ['algorithm' => $algorithm])
            ->getResourceOwner($this->token($this->claims(), $signingKey, $algorithm))
        ;

        self::assertSame('777', $owner->getId());
        self::assertSame('maks', $owner->getUsername());
        self::assertSame(Telegram::ISSUER.'/.well-known/jwks.json', (string) $this->request(0)->getUri());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideResourceOwnerIsTheVerifiedIdTokenCases(): iterable
    {
        yield 'RS256' => ['RS256'];

        yield 'ES256' => ['ES256'];

        yield 'EdDSA' => ['EdDSA'];
    }

    public function testAudienceMayBeAList(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $owner = $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims(['aud' => ['other', self::CLIENT_ID]]), $signingKey));

        self::assertSame('777', $owner->getId());
    }

    /**
     * @param array<string, mixed> $claims
     */
    #[DataProvider('provideRejectsInvalidClaimsCases')]
    public function testRejectsInvalidClaims(array $claims, string $message): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $this->expectException(TelegramIdentityProviderException::class);
        $this->expectExceptionMessageIsOrContains($message);

        $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims($claims), $signingKey));
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideRejectsInvalidClaimsCases(): iterable
    {
        yield 'another client' => [['aud' => '999'], 'ID token audience does not match the client id.'];

        yield 'another client in a list' => [['aud' => ['998', '999']], 'ID token audience does not match the client id.'];

        yield 'missing audience' => [['aud' => null], 'ID token audience does not match the client id.'];

        yield 'unexpected issuer' => [['iss' => 'https://evil.example'], 'Unexpected ID token issuer.'];

        yield 'missing subject' => [['sub' => null], 'ID token has no subject.'];

        yield 'empty subject' => [['sub' => ''], 'ID token has no subject.'];

        yield 'non-scalar subject' => [['sub' => ['777']], 'ID token has no subject.'];
    }

    public function testAcceptsNumericSubject(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $owner = $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims(['sub' => 777]), $signingKey));

        self::assertSame('777', $owner->getId());
    }

    public function testWrapsExpiredToken(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $exception = $this->catch(fn (): TelegramResourceOwner => $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims(['exp' => time() - 3600, 'iat' => time() - 7200]), $signingKey)));

        self::assertInstanceOf(ExpiredException::class, $exception->getPrevious());
    }

    public function testToleratesClockSkewWithinLeeway(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $owner = $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims(['iat' => time() + 30]), $signingKey));

        self::assertSame('777', $owner->getId());
        self::assertSame(0, JWT::$leeway);
    }

    public function testRejectsClockSkewBeyondLeeway(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');

        $exception = $this->catch(fn (): TelegramResourceOwner => $this->provider([$this->jwks($jwk)], ['leeway' => 10])->getResourceOwner($this->token($this->claims(['iat' => time() + 30]), $signingKey)));

        self::assertInstanceOf(BeforeValidException::class, $exception->getPrevious());
        self::assertSame(0, JWT::$leeway);
    }

    public function testWrapsTokenSignedWithAnotherKey(): void
    {
        [, $jwk] = $this->key('RS256');
        [$anotherKey] = $this->key('RS256');

        $exception = $this->catch(fn (): TelegramResourceOwner => $this->provider([$this->jwks($jwk)])->getResourceOwner($this->token($this->claims(), $anotherKey)));

        self::assertInstanceOf(SignatureInvalidException::class, $exception->getPrevious());
    }

    public function testRejectsMissingIdToken(): void
    {
        $this->expectException(TelegramIdentityProviderException::class);
        $this->expectExceptionMessageIsOrContains('Telegram did not return an ID token.');

        $this->provider()->getResourceOwner(new AccessToken(['access_token' => 'x']));
    }

    public function testRejectsJwksThatIsNotJson(): void
    {
        [$signingKey] = $this->key('RS256');

        $this->expectException(TelegramIdentityProviderException::class);
        $this->expectExceptionMessageIsOrContains('Telegram returned an invalid JWKS.');

        $this->provider([new Response(200, ['Content-Type' => 'text/plain'], 'nope')])->getResourceOwner($this->token($this->claims(), $signingKey));
    }

    public function testWrapsMalformedJwks(): void
    {
        [$signingKey] = $this->key('RS256');

        $exception = $this->catch(fn (): TelegramResourceOwner => $this->provider([$this->json(['no' => 'keys'])])->getResourceOwner($this->token($this->claims(), $signingKey)));

        self::assertInstanceOf(\UnexpectedValueException::class, $exception->getPrevious());
    }

    public function testRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageIsOrContains('Unsupported ID token algorithm "HS256"');

        $this->provider([], ['algorithm' => 'HS256']);
    }

    public function testAuthorizationUrl(): void
    {
        $provider = $this->provider();
        $url = $provider->getAuthorizationUrl();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        self::assertStringStartsWith(Telegram::ISSUER.'/auth?', $url);
        self::assertSame('openid', $query['scope']);
        self::assertSame('code', $query['response_type']);
        self::assertSame(self::CLIENT_ID, $query['client_id']);
        self::assertSame(self::REDIRECT_URI, $query['redirect_uri']);
        self::assertSame($provider->getState(), $query['state']);
        self::assertSame('S256', $query['code_challenge_method']);
        $verifier = $provider->getPkceCode();
        self::assertIsString($verifier);
        self::assertSame(mb_rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='), $query['code_challenge']);
    }

    public function testScopesAreSpaceSeparated(): void
    {
        $url = $this->provider()->getAuthorizationUrl(['scope' => ['openid', 'profile', 'phone']]);

        self::assertStringContainsString('scope=openid%20profile%20phone', $url);
    }

    public function testPkceCanBeDisabled(): void
    {
        $url = $this->provider([], ['pkceMethod' => null])->getAuthorizationUrl();

        self::assertStringNotContainsString('code_challenge', $url);
    }

    public function testTokenRequestUsesBasicAuthAndPkceVerifier(): void
    {
        $provider = $this->provider([$this->json(['access_token' => 'at', 'token_type' => 'Bearer', 'expires_in' => 3600, 'id_token' => 'jwt'])]);
        $provider->setPkceCode('verifier');

        $token = $provider->getAccessToken('authorization_code', ['code' => 'the-code']);

        self::assertSame('jwt', $token->getValues()['id_token']);
        $request = $this->request(0);
        self::assertSame(Telegram::ISSUER.'/token', (string) $request->getUri());
        self::assertSame('Basic '.base64_encode(self::CLIENT_ID.':secret'), $request->getHeaderLine('Authorization'));
        parse_str((string) $request->getBody(), $body);
        ksort($body);
        self::assertSame(['code' => 'the-code', 'code_verifier' => 'verifier', 'grant_type' => 'authorization_code', 'redirect_uri' => self::REDIRECT_URI], $body);
    }

    public function testUserSuppliedOptionProviderWins(): void
    {
        $http = new Client(['handler' => $this->handler([$this->json(['access_token' => 'at'])])]);
        $provider = new Telegram(
            ['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret', 'redirectUri' => self::REDIRECT_URI],
            ['httpClient' => $http, 'optionProvider' => new PostAuthOptionProvider()],
        );

        $provider->getAccessToken('authorization_code', ['code' => 'the-code']);

        self::assertFalse($this->request(0)->hasHeader('Authorization'));
        self::assertStringContainsString('client_secret=secret', (string) $this->request(0)->getBody());
    }

    public function testTokenErrorPrefersErrorDescription(): void
    {
        $exception = $this->catch(fn () => $this->provider([$this->json(['error' => 'invalid_grant', 'error_description' => 'Code expired'], 400)])->getAccessToken('authorization_code', ['code' => 'x']));

        self::assertSame('Code expired', $exception->getMessage());
        self::assertSame(400, $exception->getCode());
        self::assertSame(['error' => 'invalid_grant', 'error_description' => 'Code expired'], $exception->getResponseBody());
    }

    public function testTokenErrorWithHttp200(): void
    {
        // What oauth.telegram.org/token actually returns for an expired or unknown code.
        $exception = $this->catch(fn () => $this->provider([$this->json(['error' => 'invalid_grant'])])->getAccessToken('authorization_code', ['code' => 'x']));

        self::assertSame('invalid_grant', $exception->getMessage());
        self::assertSame(200, $exception->getCode());
        self::assertSame(['error' => 'invalid_grant'], $exception->getResponseBody());
    }

    public function testTokenErrorFallsBackToReasonPhrase(): void
    {
        $exception = $this->catch(fn () => $this->provider([new Response(502, [], 'Bad gateway')])->getAccessToken('authorization_code', ['code' => 'x']));

        self::assertSame('Bad Gateway', $exception->getMessage());
        self::assertSame(502, $exception->getCode());
    }

    public function testHasNoResourceOwnerDetailsUrl(): void
    {
        $this->expectException(\LogicException::class);

        $this->provider()->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'x']));
    }

    public function testFetchesJwksOnEveryLoginWithoutCache(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');
        $provider = $this->provider([$this->jwks($jwk), $this->jwks($jwk)]);

        $provider->getResourceOwner($this->token($this->claims(), $signingKey));
        $provider->getResourceOwner($this->token($this->claims(), $signingKey));

        self::assertCount(2, $this->history);
    }

    public function testCachedJwksAvoidsHttpCall(): void
    {
        [$signingKey, $jwk] = $this->key('RS256');
        $cache = new Psr16Cache(new ArrayAdapter());
        $provider = $this->provider([$this->jwks($jwk)], ['jwksCache' => $cache]);

        $provider->getResourceOwner($this->token($this->claims(), $signingKey));
        $provider->getResourceOwner($this->token($this->claims(), $signingKey));

        self::assertCount(1, $this->history);
        self::assertSame(['keys' => [$jwk]], $cache->get('oauth2_telegram_jwks'));
    }

    public function testRefetchesJwksOnceWhenKeysRotated(): void
    {
        [, $oldJwk] = $this->key('RS256');
        [$newKey, $newJwk] = $this->key('RS256', 'new');
        $cache = new Psr16Cache(new ArrayAdapter());
        $cache->set('oauth2_telegram_jwks', ['keys' => [$oldJwk]]);

        $owner = $this->provider([$this->jwks($newJwk)], ['jwksCache' => $cache])->getResourceOwner($this->token($this->claims(), $newKey, 'RS256', 'new'));

        self::assertSame('777', $owner->getId());
        self::assertCount(1, $this->history);
        self::assertSame(['keys' => [$newJwk]], $cache->get('oauth2_telegram_jwks'));
    }

    /**
     * @param list<Response>       $responses
     * @param array<string, mixed> $options
     */
    private function provider(array $responses = [], array $options = []): Telegram
    {
        return new Telegram(
            $options + ['clientId' => self::CLIENT_ID, 'clientSecret' => 'secret', 'redirectUri' => self::REDIRECT_URI],
            ['httpClient' => new Client(['handler' => $this->handler($responses)])],
        );
    }

    /**
     * @param list<Response> $responses
     */
    private function handler(array $responses): HandlerStack
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        $history = $this->history; // history() takes it by reference, which a typed property can't satisfy
        $stack->push(Middleware::history($history));

        return $stack;
    }

    private function request(int $index): RequestInterface
    {
        $entry = $this->history[$index] ?? null;
        self::assertIsArray($entry);
        self::assertInstanceOf(RequestInterface::class, $entry['request'] ?? null);

        return $entry['request'];
    }

    private function catch(callable $call): TelegramIdentityProviderException
    {
        try {
            $call();
        } catch (TelegramIdentityProviderException $telegramIdentityProviderException) {
            return $telegramIdentityProviderException;
        }

        self::fail('Expected '.TelegramIdentityProviderException::class);
    }

    /**
     * @param array<mixed> $data
     */
    private function json(array $data, int $status = 200): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], json_encode($data, JSON_THROW_ON_ERROR));
    }

    /**
     * @param array<string, string> $jwk
     */
    private function jwks(array $jwk): Response
    {
        return $this->json(['keys' => [$jwk]]);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function token(array $claims, string $signingKey, string $algorithm = 'RS256', string $kid = 'test'): AccessToken
    {
        return new AccessToken(['access_token' => 'x', 'id_token' => JWT::encode(array_filter($claims, static fn (mixed $v): bool => null !== $v), $signingKey, $algorithm, $kid)]);
    }

    /**
     * @param array<string, mixed> $override
     *
     * @return array<string, mixed>
     */
    private function claims(array $override = []): array
    {
        return $override + [
            'iss' => Telegram::ISSUER,
            'aud' => self::CLIENT_ID,
            'sub' => '777',
            'preferred_username' => 'maks',
            'iat' => time(),
            'exp' => time() + 600,
        ];
    }

    /**
     * A fresh signing key and its public JWK.
     *
     * @return array{string, array<string, string>}
     */
    private function key(string $algorithm, string $kid = 'test'): array
    {
        if ('EdDSA' === $algorithm) {
            $pair = sodium_crypto_sign_keypair();

            return [
                base64_encode(sodium_crypto_sign_secretkey($pair)),
                ['kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'kid' => $kid, 'x' => $this->base64Url(sodium_crypto_sign_publickey($pair))],
            ];
        }

        $key = openssl_pkey_new('ES256' === $algorithm
            ? ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']
            : ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        self::assertTrue(openssl_pkey_export($key, $pem));
        self::assertIsString($pem);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);

        $jwk = ['alg' => $algorithm, 'kid' => $kid, 'use' => 'sig'];
        if ('ES256' === $algorithm) {
            self::assertIsArray($details['ec']);
            self::assertIsString($details['ec']['x']);
            self::assertIsString($details['ec']['y']);
            $jwk += [
                'kty' => 'EC',
                'crv' => 'P-256',
                'x' => $this->base64Url(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
                'y' => $this->base64Url(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
            ];
        } else {
            self::assertIsArray($details['rsa']);
            self::assertIsString($details['rsa']['n']);
            self::assertIsString($details['rsa']['e']);
            $jwk += ['kty' => 'RSA', 'n' => $this->base64Url($details['rsa']['n']), 'e' => $this->base64Url($details['rsa']['e'])];
        }

        return [$pem, $jwk];
    }

    private function base64Url(string $binary): string
    {
        return mb_rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
