<div align="center">

# oauth2-telegram

[![CI](https://img.shields.io/github/actions/workflow/status/maks-oleksyuk/oauth2-telegram/ci.yml?branch=main&style=flat&label=CI)](//github.com/maks-oleksyuk/oauth2-telegram/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/codecov/c/github/maks-oleksyuk/oauth2-telegram?style=flat&logo=codecov&logoColor=white)](//codecov.io/gh/maks-oleksyuk/oauth2-telegram)
[![PHP Version](https://img.shields.io/badge/PHP-8.4%2B-777bb4?style=flat&logo=php&logoColor=white)](composer.json)
[![Latest Version](https://img.shields.io/packagist/v/oleksyuk/oauth2-telegram.svg?style=flat&logo=packagist&logoColor=white&color=F28D1A)](//packagist.org/packages/oleksyuk/oauth2-telegram)
[![Total Downloads](https://img.shields.io/packagist/dt/oleksyuk/oauth2-telegram.svg?style=flat&logo=packagist&logoColor=white&color=F28D1A)](//packagist.org/packages/oleksyuk/oauth2-telegram/stats)

[Log in with Telegram](//core.telegram.org/bots/telegram-login) (OpenID Connect) provider for [league/oauth2-client](//github.com/thephpleague/oauth2-client).

</div>

Targets the OpenID Connect flow at `https://oauth.telegram.org`, not the legacy Login Widget that signs the data with the bot token.
Framework-agnostic: works with plain League, `knpuniversity/oauth2-client-bundle`, Laravel and anything else built on League.

## Installation

```bash
composer require oleksyuk/oauth2-telegram
```

## Setup in Telegram

1. Create a bot (or pick an existing one) in [@BotFather](//t.me/BotFather).
2. Open *Bot Settings → Login Widget* and add every redirect URI of your app to *Allowed URLs*.
3. Note the *Client ID* (the bot id) and the *Client Secret*.
4. Optionally pick the ID token signing algorithm under *Advanced* (`RS256` by default). If you change it, pass the same value as the `algorithm` option.

## Usage

```php
use Oleksyuk\OAuth2\Client\Provider\TelegramProvider;

$provider = new TelegramProvider([
    'clientId' => '1234567890',
    'clientSecret' => 'your-client-secret',
    'redirectUri' => 'https://example.com/auth/telegram/callback',
]);

if (!isset($_GET['code'])) {
    $url = $provider->getAuthorizationUrl(['scope' => ['openid', 'profile']]);

    // Keep the state (CSRF) and the PKCE verifier for the callback request.
    $_SESSION['oauth2state'] = $provider->getState();
    $_SESSION['oauth2pkce'] = $provider->getPkceCode();

    header('Location: '.$url);
    exit;
}

if (!isset($_GET['state'], $_SESSION['oauth2state']) || !hash_equals($_SESSION['oauth2state'], $_GET['state'])) {
    unset($_SESSION['oauth2state']);
    exit('Invalid state');
}

$provider->setPkceCode($_SESSION['oauth2pkce']);
$token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

// The resource owner is the verified ID token: there is no extra HTTP call to a UserInfo endpoint.
$user = $provider->getResourceOwner($token);

$user->getId();         // `sub`, stable per user: use it as the account identifier
$user->getTelegramId(); // numeric Telegram user id (`id`, with the `profile` scope)
$user->getUsername();   // `preferred_username`, may be null
$user->getName();
$user->getPicture();
$user->getPhoneNumber(); // with the `phone` scope
$user->toArray();        // all claims
```

Every getter except `getId()` returns `null` when the claim is missing.

### Options

| Option         | Default          | Description                                                                                      |
|----------------|------------------|--------------------------------------------------------------------------------------------------|
| `algorithm`    | `RS256`          | ID token signing algorithm chosen in @BotFather: `RS256`, `ES256`, `ES256K` or `EdDSA` (needs `ext-sodium`). |
| `pkceMethod`   | `S256`           | PKCE method; `null` disables PKCE.                                                               |
| `jwksCache`    | `null`           | A PSR-16 cache (`psr/simple-cache`) for Telegram's signing keys. Without it the keys are fetched on every login. |
| `jwksCacheTtl` | `3600`           | Cache lifetime in seconds. On a signature failure with cached keys the set is refetched once (key rotation). |

### Scopes

| Scope                 | Claims                                                 |
|-----------------------|--------------------------------------------------------|
| `openid` (required)   | `sub`, `iss`, `aud`, `iat`, `exp`                      |
| `profile`             | `id`, `name`, `preferred_username`, `picture`          |
| `phone`               | `phone_number` (asks the user for consent)             |
| `telegram:bot_access` | none: lets the bot send messages to the user           |

The default scope is `openid`. With `EdDSA` or `ES256K` signing Telegram allows only `openid`.

### Login page language

Telegram's docs list no language parameter, but `lang` on the authorization URL switches the login page language.
It is **undocumented** and may stop working:

```php
$url = $provider->getAuthorizationUrl(['lang' => 'uk']);
```

### Errors

Every failure throws `League\OAuth2\Client\Provider\Exception\IdentityProviderException`: an error from the token
endpoint (with Telegram's `error_description`/`error` as the message when present), a missing ID token, a wrong
`iss`/`aud`/`sub`, an unusable JWKS and any signature or time check failure. In the last case the original
`firebase/php-jwt` exception (`ExpiredException`, `SignatureInvalidException`, `BeforeValidException`, …) is
available via `getPrevious()`.

## Symfony (`knpuniversity/oauth2-client-bundle`)

```php
// config/packages/knpu_oauth2_client.php
namespace Symfony\Component\DependencyInjection\Loader\Configurator;

use Oleksyuk\OAuth2\Client\Provider\TelegramProvider;

return App::config([
    'knpu_oauth2_client' => [
        'clients' => [
            'telegram' => [
                'type' => 'generic',
                'provider_class' => TelegramProvider::class,
                'client_id' => '%env(TELEGRAM_CLIENT_ID)%',
                'client_secret' => '%env(TELEGRAM_CLIENT_SECRET)%',
                'redirect_route' => 'auth_oauth_callback',
                'redirect_params' => ['provider' => 'telegram'],
                // The bundle doesn't keep the PKCE verifier between redirect and callback for generic clients.
                'provider_options' => ['pkceMethod' => null],
            ],
        ],
    ],
]);
```

Extra authorization parameters go as the second argument of `redirect()`:

```php
return $clientRegistry->getClient('telegram')->redirect(['openid', 'profile'], ['lang' => 'uk']);
```

To keep PKCE on, store `$client->getOAuth2Provider()->getPkceCode()` in the session after building the redirect and call
`setPkceCode()` on the provider before `getAccessToken()`.

## Security

Verified on every `getResourceOwner()` call:

- the ID token signature against Telegram's JWKS (`https://oauth.telegram.org/.well-known/jwks.json`);
- `exp`, `nbf` and `iat`;
- `iss` is `https://oauth.telegram.org`;
- `aud` contains your client id;
- `sub` is present.

CSRF protection is League's `state` (check it in your callback, as above), and PKCE (`S256`) is on by default.
`nonce` is not supported: Telegram's manual OpenID Connect flow doesn't document it.

## Development

```bash
task lint            # PHPStan (max level), PHP CS Fixer, Rector, composer validate
task test            # PHPUnit
task test:coverage   # PHPUnit + coverage report in build/ (needs Xdebug or PCOV)
task fix             # auto-fix CS Fixer / Rector issues
```

## License

MIT, see [LICENSE.md](LICENSE.md).
