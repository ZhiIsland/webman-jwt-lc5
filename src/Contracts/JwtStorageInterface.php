<?php
namespace Zh\Jwt\Contracts;

interface JwtStorageInterface
{
    public function blacklist(string $guard, string $jti, int $ttl): void;

    public function isBlacklisted(string $guard, string $jti): bool;

    public function bindActiveToken(string $guard, string $userId, string $deviceId, string $jti, int $ttl): void;

    public function getActiveTokens(string $guard, string $userId): array;

    public function unbindActiveToken(string $guard, string $userId, string $deviceId): void;

    public function markRefreshUsed(string $guard, string $jti, int $ttl): void;

    public function isRefreshUsed(string $guard, string $jti): bool;

    public function pushDeviceAndMaybePop(string $guard, string $userId, string $deviceId, int $maxDevices): ?string;
}