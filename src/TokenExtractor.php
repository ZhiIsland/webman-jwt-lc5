<?php
namespace Zh\Jwt;

use Webman\Http\Request;
use Zh\Jwt\Support\Config;

class TokenExtractor
{
    public static function fromRequest(Request $request, string $guard): ?string
    {
        $guardConf = Config::get("guards.{$guard}", []);
        $locations = $guardConf['token_locations'] ?? Config::get('token_locations', ['header','cookie','query']);
        $headerKey = (string) Config::get('token_key', 'Authorization');
        $prefix    = (string) Config::get('token_prefix', 'Bearer');
        $cookieName= (string) Config::get('cookie_name', 'access_token');
        $queryName = (string) Config::get('query_name', 'token');

        foreach ($locations as $loc) {
            if ($loc === 'header') {
                $header = $request->header($headerKey);
                if ($header) {
                    if ($prefix && stripos($header, $prefix.' ') === 0) {
                        return trim(substr($header, strlen($prefix)));
                    }
                    return $header;
                }
            } elseif ($loc === 'cookie') {
                $cookie = $request->cookie($cookieName);
                if (!empty($cookie)) return $cookie;
            } elseif ($loc === 'query') {
                $q = $request->get($queryName);
                if (!empty($q)) return $q;
            }
        }
        return null;
    }

    public static function fromRequestRefresh(Request $request, string $guard): ?string
    {
        $guardConf = Config::get("guards.{$guard}", []);
        $locations = $guardConf['refresh_token_locations'] ?? Config::get('refresh_token_locations', ['header','cookie','query']);
        $headerKey = (string) Config::get('refresh_token_key', 'X-Refresh-Token');
        $cookieName= (string) Config::get('refresh_cookie_name', 'refresh_token');
        $queryName = (string) Config::get('refresh_query_name', 'refresh_token');

        foreach ($locations as $loc) {
            if ($loc === 'header') {
                $header = $request->header($headerKey);
                if (!empty($header)) return trim($header);
            } elseif ($loc === 'cookie') {
                $cookie = $request->cookie($cookieName);
                if (!empty($cookie)) return $cookie;
            } elseif ($loc === 'query') {
                $q = $request->get($queryName);
                if (!empty($q)) return $q;
            }
        }
        return null;
    }

    // 新增：无需传 Request，自动从当前请求提取（Webman 环境）
    public static function fromCurrentRequest(string $guard): ?string
    {
        // 优先 Webman\App::request()
        if (class_exists(\Webman\App::class)) {
            $req = \Webman\App::request();
            if ($req) {
                return self::fromRequest($req, $guard);
            }
        }
        // 其次容器（某些场景）
        if (class_exists(\Webman\Container::class) && \Webman\Container::has(\Webman\Http\Request::class)) {
            $req = \Webman\Container::get(\Webman\Http\Request::class);
            return self::fromRequest($req, $guard);
        }
        return null;
    }

    public static function fromCurrentRequestRefresh(string $guard): ?string
    {
        if (class_exists(\Webman\App::class)) {
            $req = \Webman\App::request();
            if ($req) {
                return self::fromRequestRefresh($req, $guard);
            }
        }
        if (class_exists(\Webman\Container::class) && \Webman\Container::has(\Webman\Http\Request::class)) {
            $req = \Webman\Container::get(\Webman\Http\Request::class);
            return self::fromRequestRefresh($req, $guard);
        }
        return null;
    }
}