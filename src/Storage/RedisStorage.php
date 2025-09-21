<?php
namespace Zhiisland\WebmanJwtLc5\Storage;

use Zhiisland\WebmanJwtLc5\Contracts\JwtStorageInterface;
use Zhiisland\WebmanJwtLc5\Support\Config;
use support\Redis;

class RedisStorage implements JwtStorageInterface
{
    protected string $prefix;

    public function __construct()
    {
        $this->prefix = Config::get('redis.prefix', 'jwt:');
    }

    protected function blKey(string $guard, string $jti): string
    {
        return "{$this->prefix}bl:{$guard}:{$jti}";
    }

    protected function activeKey(string $guard, string $userId): string
    {
        return "{$this->prefix}active:{$guard}:{$userId}";
    }

    protected function deviceQueueKey(string $guard, string $userId): string
    {
        return "{$this->prefix}devices:{$guard}:{$userId}";
    }

    protected function rtUsedKey(string $guard, string $jti): string
    {
        return "{$this->prefix}rt:used:{$guard}:{$jti}";
    }

    public function blacklist(string $guard, string $jti, int $ttl): void
    {
        Redis::setex($this->blKey($guard, $jti), max(1, $ttl), 1);
    }

    public function isBlacklisted(string $guard, string $jti): bool
    {
        return (bool) Redis::exists($this->blKey($guard, $jti));
    }

    public function bindActiveToken(string $guard, string $userId, string $deviceId, string $jti, int $ttl): void
    {
        Redis::hSet($this->activeKey($guard, $userId), $deviceId, $jti);
        Redis::expire($this->activeKey($guard, $userId), max(3600, $ttl));
    }

    public function getActiveTokens(string $guard, string $userId): array
    {
        return Redis::hGetAll($this->activeKey($guard, $userId)) ?: [];
    }

    public function unbindActiveToken(string $guard, string $userId, string $deviceId): void
    {
        Redis::hDel($this->activeKey($guard, $userId), $deviceId);
    }

    public function markRefreshUsed(string $guard, string $jti, int $ttl): void
    {
        Redis::setex($this->rtUsedKey($guard, $jti), max(1, $ttl), 1);
    }

    public function isRefreshUsed(string $guard, string $jti): bool
    {
        return (bool) Redis::exists($this->rtUsedKey($guard, $jti));
    }

    public function pushDeviceAndMaybePop(string $guard, string $userId, string $deviceId, int $maxDevices): ?string
    {
        $queueKey = $this->deviceQueueKey($guard, $userId);
        Redis::lRem($queueKey, 0, $deviceId);
        Redis::rPush($queueKey, $deviceId);
        $len = Redis::lLen($queueKey);
        $popped = null;
        while ($len > $maxDevices) {
            $popped = Redis::lPop($queueKey);
            $len--;
        }
        Redis::expire($queueKey, 7 * 24 * 3600);
        return $popped ?: null;
    }
}