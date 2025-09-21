<?php
namespace Zh\Jwt\Utils;

use Lcobucci\JWT\Token\DataSet;
use Zh\Jwt\JwtManager;
use Zh\Jwt\Support\Config;
use Zh\Jwt\TokenExtractor;
use Zh\Jwt\Exceptions\TokenNotProvidedException;

/**
 * 便捷工具：参考你的 meta\utils\JWTUtil 思路，实现自动获取与解析
 */
class JWTUtil
{
    public static function claimsToArray(DataSet $claims): array
    {
        return $claims->all();
    }

    // 自动获取 access token（去掉前缀）
    public static function getToken(?string $guard = null): string
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $token = TokenExtractor::fromCurrentRequest($g);
        if (!$token) {
            throw new TokenNotProvidedException('Token not provided');
        }
        return $token;
    }

    // 自动获取 refresh token
    public static function getRefreshToken(?string $guard = null): string
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $token = TokenExtractor::fromCurrentRequestRefresh($g);
        if (!$token) {
            throw new \RuntimeException('Refresh token not provided');
        }
        return $token;
    }

    // 解析当前请求的 access claims（不做签名/时间校验）
    public static function getParserData(?string $guard = null): array
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $token = self::getToken($g);
        $plain = (new JwtManager($g))->parse($token);
        return $plain->claims()->all();
    }

    // 验证（签名+时间+iss/aud等），返回 Plain Token
    public static function verify(?string $guard = null, ?string $token = null)
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $t = $token ?: self::getToken($g);
        return (new JwtManager($g))->verifyAccess($t);
    }

    // 刷新（自动从请求获取 refresh）
    public static function refresh(?string $guard = null, ?string $refreshToken = null): array
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $rt = $refreshToken ?: self::getRefreshToken($g);
        return (new JwtManager($g))->refresh($rt);
    }

    // 失效（自动从请求获取 access）
    public static function invalidate(?string $guard = null, ?string $token = null): void
    {
        $g = $guard ?: (string) Config::get('default_guard', 'frontend');
        $t = $token ?: self::getToken($g);
        (new JwtManager($g))->invalidate($t);
    }
}