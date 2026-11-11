<?php

declare(strict_types=1);

namespace Oleksyuk\OAuth2\Client\Tests\Provider;

use Oleksyuk\OAuth2\Client\Provider\TelegramResourceOwner;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(TelegramResourceOwner::class)]
final class TelegramResourceOwnerTest extends TestCase
{
    public function testReadsClaims(): void
    {
        $claims = [
            'sub' => 'abc-subject',
            'id' => 123456789,
            'name' => 'Maks Oleksyuk',
            'given_name' => 'Maks',
            'family_name' => 'Oleksyuk',
            'preferred_username' => 'maks',
            'picture' => 'https://t.me/i/userpic/320/maks.jpg',
            'phone_number' => '+380000000000',
            'phone_number_verified' => true,
        ];
        $owner = new TelegramResourceOwner($claims);

        self::assertSame('abc-subject', $owner->getId());
        self::assertSame(123456789, $owner->getTelegramId());
        self::assertSame('Maks Oleksyuk', $owner->getName());
        self::assertSame('Maks', $owner->getGivenName());
        self::assertSame('Oleksyuk', $owner->getFamilyName());
        self::assertSame('maks', $owner->getUsername());
        self::assertSame('https://t.me/i/userpic/320/maks.jpg', $owner->getPicture());
        self::assertSame('+380000000000', $owner->getPhoneNumber());
        self::assertTrue($owner->isPhoneNumberVerified());
        self::assertSame($claims, $owner->toArray());
    }

    public function testNumericSubjectIsAString(): void
    {
        self::assertSame('777', new TelegramResourceOwner(['sub' => 777, 'id' => 42])->getId());
    }

    public function testMissingClaimsAreNull(): void
    {
        $owner = new TelegramResourceOwner([]);

        self::assertSame('', $owner->getId());
        self::assertNull($owner->getTelegramId());
        self::assertNull($owner->getName());
        self::assertNull($owner->getGivenName());
        self::assertNull($owner->getFamilyName());
        self::assertNull($owner->getUsername());
        self::assertNull($owner->getPicture());
        self::assertNull($owner->getPhoneNumber());
        self::assertNull($owner->isPhoneNumberVerified());
        self::assertSame([], $owner->toArray());
    }

    public function testOddTypedClaimsAreNull(): void
    {
        $owner = new TelegramResourceOwner([
            'sub' => ['x'],
            'id' => '123',
            'name' => 1,
            'preferred_username' => false,
            'phone_number_verified' => 'true',
        ]);

        self::assertSame('', $owner->getId());
        self::assertNull($owner->getTelegramId());
        self::assertNull($owner->getName());
        self::assertNull($owner->getUsername());
        self::assertNull($owner->isPhoneNumberVerified());
    }
}
