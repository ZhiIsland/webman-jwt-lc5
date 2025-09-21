<?php
namespace Zh\Jwt\Fluent;

use Lcobucci\JWT\Token\Plain;
use Zh\Jwt\JwtManager;
use Zh\Jwt\Support\Config;
use Zh\Jwt\TokenExtractor;

/**
 * 链式操作的 JWT 构建器与执行器
 *
 * - 可不传 token，自动从当前请求中获取
 */
class JwtFluent
{
    protected ?string $guard = null;
    protected array $claims = [];
    protected ?string $client = null;
    protected ?string $deviceId = null;

    protected ?int $accessTtlOverride = null;
    protected ?int $refreshTtlOverride = null;

    protected ?string $accessTokenString = null;
    protected ?string $refreshTokenString = null;

    public static function make(?string $guard = null): self
    {
        $self = new self();
        $self->guard = $guard ?: (string) Config::get('default_guard', 'frontend');
        return $self;
    }

    public function guard(string $guard): self
    {
        $this->guard = $guard;
        return $this;
    }

    public function client(string $client): self
    {
        $this->client = $client;
        return $this;
    }

    public function device(string $deviceId): self
    {
        $this->deviceId = $deviceId;
        return $this;
    }

    public function claims(array $claims): self
    {
        $this->claims = array_merge($this->claims, $claims);
        return $this;
    }

    public function ttl(int $seconds): self
    {
        $this->accessTtlOverride = max(1, $seconds);
        return $this;
    }

    public function refreshTtl(int $seconds): self
    {
        $this->refreshTtlOverride = max(1, $seconds);
        return $this;
    }

    public function access(string $jwt): self
    {
        $this->accessTokenString = $jwt;
        return $this;
    }

    public function refreshToken(string $jwt): self
    {
        $this->refreshTokenString = $jwt;
        return $this;
    }

    public function issue(string $userId): array
    {
        $claims = $this->claims;
        if ($this->accessTtlOverride !== null) $claims['access_exp'] = $this->accessTtlOverride;
        if ($this->refreshTtlOverride !== null) $claims['refresh_exp'] = $this->refreshTtlOverride;
        if (!isset($claims['client']) && $this->client) $claims['client'] = $this->client;

        $jm = new JwtManager($this->guard);
        return $jm->issueTokens($userId, $claims, $this->deviceId);
    }

    public function verifyAccess(?string $jwt = null): Plain
    {
        $jwtStr = $jwt ?? $this->accessTokenString ?? TokenExtractor::fromCurrentRequest($this->guard);
        if (!$jwtStr) {
            throw new \Zh\Jwt\Exceptions\TokenNotProvidedException('Token not provided');
        }
        return (new JwtManager($this->guard))->verifyAccess($jwtStr);
    }

    public function refresh(?string $refreshJwt = null): array
    {
        $jwtStr = $refreshJwt ?? $this->refreshTokenString ?? TokenExtractor::fromCurrentRequestRefresh($this->guard);
        if (!$jwtStr) {
            throw new \RuntimeException('Refresh token not provided');
        }
        return (new JwtManager($this->guard))->refresh($jwtStr);
    }

    public function invalidate(?string $jwt = null): void
    {
        $jwtStr = $jwt ?? $this->accessTokenString ?? TokenExtractor::fromCurrentRequest($this->guard);
        if (!$jwtStr) {
            throw new \Zh\Jwt\Exceptions\TokenNotProvidedException('Token not provided');
        }
        (new JwtManager($this->guard))->invalidate($jwtStr);
    }

    public function invalidateUser(string $userId, ?string $client = null, ?string $deviceId = null): void
    {
        $jm = new JwtManager($this->guard);
        if ($client !== null && $deviceId !== null) {
            $jm->invalidateUser($userId, "{$client}:{$deviceId}");
            return;
        }
        if ($client !== null) {
            $jm->invalidateUserByClient($userId, $client);
            return;
        }
        $jm->invalidateUser($userId, null);
    }
}