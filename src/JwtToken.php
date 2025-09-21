<?php
namespace Zhiisland\WebmanJwtLc5;

use Webman\Container;
use Webman\Http\Request;
use Zhiisland\WebmanJwtLc5\Support\Config;
use Zhiisland\WebmanJwtLc5\Contracts\UserResolverInterface;

class JwtToken
{
    public const string TOKEN_CLIENT_WEB    = 'WEB';
    public const string TOKEN_CLIENT_MOBILE = 'MOBILE';
    public const string TOKEN_CLIENT_WECHAT = 'WECHAT';
    public const string TOKEN_CLIENT_ADMIN  = 'ADMIN';
    public const string TOKEN_CLIENT_API    = 'API';
    public const string TOKEN_CLIENT_OTHER  = 'OTHER';

    protected static function guard(): string
    {
        return (string) Config::get('default_guard', 'frontend');
    }

    protected static function request(): ?Request
    {
        return Container::has(Request::class) ? Container::get(Request::class) : null;
    }

    public static function generateToken(array $extend, ?string $guard = null, ?string $client = null, ?string $deviceId = null): array
    {
        $g = $guard ?: self::guard();
        $jwt = new JwtManager($g);

        $userId = (string) ($extend['id'] ?? $extend['uid'] ?? $extend['user_id'] ?? '');
        if ($userId === '') {
            throw new \InvalidArgumentException('generateToken requires id/uid/user_id in $extend');
        }

        $claims = $extend;
        unset($claims['id'], $claims['uid'], $claims['user_id']);

        // 单次覆盖 ttl
        if (isset($extend['access_exp']))  $claims['access_exp']  = (int) $extend['access_exp'];
        if (isset($extend['refresh_exp'])) $claims['refresh_exp'] = (int) $extend['refresh_exp'];

        $client = $client ?: (string) Config::get('client_default', self::TOKEN_CLIENT_WEB);
        $claims['client'] = $client;

        return $jwt->issueTokens($userId, $claims, $deviceId);
    }

    public static function getCurrentId(?string $guard = null): ?string
    {
        $req = self::request();
        if (!$req || !isset($req->jwt_claims)) return null;
        return $req->jwt_claims['sub'] ?? null;
    }

    public static function getExtend(?string $guard = null): array
    {
        $req = self::request();
        if (!$req || !isset($req->jwt_claims)) return [];
        return $req->jwt_claims;
    }

    public static function getExtendVal(string $key, $default = null, ?string $guard = null)
    {
        $claims = self::getExtend($guard);
        return $claims[$key] ?? $default;
    }

    public static function getTokenExp(): ?int
    {
        $req = self::request();
        if (!$req || !isset($req->jwt_token)) return null;
        $token = $req->jwt_token;
        $exp = $token->claims()->get('exp');
        if ($exp instanceof \DateTimeImmutable) {
            return $exp->getTimestamp() - time();
        }
        if (is_int($exp)) {
            return $exp - time();
        }
        return null;
    }

    public static function refreshToken(?string $guard = null): array
    {
        $g = $guard ?: self::guard();
        $req = self::request();
        if (!$req) {
            throw new \RuntimeException('No request context available');
        }
        $rt = TokenExtractor::fromRequestRefresh($req, $g);
        if (!$rt) {
            throw new \RuntimeException('Refresh token not provided');
        }
        return (new JwtManager($g))->refresh($rt);
    }

    public static function clear(?string $guard = null, ?string $client = null): void
    {
        $g = $guard ?: self::guard();
        $req = self::request();
        if (!$req) return;

        $jwt = new JwtManager($g);

        if (isset($req->jwt_token)) {
            $jwt->invalidate($req->jwt_token->toString());
        }

        if ($client) {
            $uid = self::getCurrentId($g);
            if ($uid) {
                $jwt->invalidateUserByClient($uid, $client);
            }
        }
    }

    public static function getUser(?string $guard = null)
    {
        $g = $guard ?: self::guard();
        $uid = self::getCurrentId($g);
        if (!$uid) return null;

        $resolver = Config::get('user_resolver');
        if (is_callable($resolver)) {
            return $resolver($g, $uid);
        }
        if (is_string($resolver) && class_exists($resolver)) {
            $r = new $resolver();
            if ($r instanceof UserResolverInterface) {
                return $r->resolve($g, $uid);
            }
        }
        return null;
    }
}