<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/**
 * Verified Telegram ID token claims. Claims depend on the granted scopes; missing or odd-typed ones read as null.
 */
final readonly class TelegramResourceOwner implements ResourceOwnerInterface
{
    /**
     * @param array<mixed> $claims
     */
    public function __construct(private array $claims) {}

    /**
     * The OIDC subject (`sub`): stable per user, and not the numeric Telegram user id (see getTelegramId()).
     */
    public function getId(): string
    {
        $sub = $this->claims['sub'] ?? null;

        return \is_string($sub) || \is_int($sub) ? (string) $sub : '';
    }

    /**
     * The numeric Telegram user id (`id`), present with the `profile` scope.
     */
    public function getTelegramId(): ?int
    {
        $id = $this->claims['id'] ?? null;

        return \is_int($id) ? $id : null;
    }

    public function getName(): ?string
    {
        return $this->string('name');
    }

    public function getGivenName(): ?string
    {
        return $this->string('given_name');
    }

    public function getFamilyName(): ?string
    {
        return $this->string('family_name');
    }

    public function getUsername(): ?string
    {
        return $this->string('preferred_username');
    }

    public function getPicture(): ?string
    {
        return $this->string('picture');
    }

    public function getPhoneNumber(): ?string
    {
        return $this->string('phone_number');
    }

    public function isPhoneNumberVerified(): ?bool
    {
        $verified = $this->claims['phone_number_verified'] ?? null;

        return \is_bool($verified) ? $verified : null;
    }

    /**
     * @return array<mixed>
     */
    public function toArray(): array
    {
        return $this->claims;
    }

    private function string(string $claim): ?string
    {
        $value = $this->claims[$claim] ?? null;

        return \is_string($value) ? $value : null;
    }
}
