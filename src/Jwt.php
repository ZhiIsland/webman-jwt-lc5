<?php
namespace Zh\Jwt;

use Lcobucci\JWT\Token\Plain;
use Webman\Http\Request;
use Zh\Jwt\Fluent\JwtFluent;
use Zh\Jwt\Support\Config;

class Jwt
{
    public static function make(?string $guard = null): JwtFluent
    {
        return JwtFluent::make($guard);
    }

    public static function guard(string $guard): JwtFluent
    {
        return JwtFluent::make($guard);
    }

    // 原有静态：显式传 token
    public static function issue(string $guard, string $userId, array $claims = [], ?string $deviceId = null): array
    {
        return (new JwtManager($guard))->issueTokens($userId, $claims, $deviceId);
    }

    public static function verify(string $guard, string $jwt): Plain
    {
        return (new JwtManager($guard))->verifyAccess($jwt);
    }

    public static function refresh(string $guard, string $refreshJwt): array
    {
        return (new JwtManager($guard))->refresh($refreshJwt);
    }

    public static function invalidate(string $guard, string $jwt): void
    {
        (new JwtManager($guard))->invalidate($jwt);
    }

    // 新增：无需显式传 token（自动从当前请求中获取）
    public static function verifyFromRequest(?string $guard = null): Plain
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $jwt = TokenExtractor::fromCurrentRequest($g);
        if (!$jwt) throw new \Zh\Jwt\Exceptions\TokenNotProvidedException('Token not provided');
        return (new JwtManager($g))->verifyAccess($jwt);
    }

    public static function refreshFromRequest(?string $guard = null): array
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $jwt = TokenExtractor::fromCurrentRequestRefresh($g);
        if (!$jwt) throw new \RuntimeException('Refresh token not provided');
        return (new JwtManager($g))->refresh($jwt);
    }

    public static function invalidateFromRequest(?string $guard = null): void
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $jwt = TokenExtractor::fromCurrentRequest($g);
        if (!$jwt) throw new \Zh\Jwt\Exceptions\TokenNotProvidedException('Token not provided');
        (new JwtManager($g))->invalidate($jwt);
    }

    // 从请求抽取上下文（保留）
    public static function fromRequest(string $guard, Request $request): object
    {
        $access = TokenExtractor::fromRequest($request, $guard);
        $refresh = TokenExtractor::fromRequestRefresh($request, $guard);

        return new class($guard, $access, $refresh) {
            public function __construct(
                private string $guard,
                private ?string $access,
                private ?string $refresh
            ) {}

            public function verify(): Plain
            {
                if (!$this->access) {
                    throw new \Zh\Jwt\Exceptions\TokenNotProvidedException('Token not provided');
                }
                return (new \Zh\Jwt\JwtManager($this->guard))->verifyAccess($this->access);
            }

            public function refresh(): array
            {
                if (!$this->refresh) {
                    throw new \RuntimeException('Refresh token not provided');
                }
                return (new \Zh\Jwt\JwtManager($this->guard))->refresh($this->refresh);
            }

            public function tokens(): array
            {
                return ['access' => $this->access, 'refresh' => $this->refresh];
            }
        };
    }

    public static function defaultGuard(): string
    {
        return (string) Config::get('default_guard', 'frontend');
    }
}