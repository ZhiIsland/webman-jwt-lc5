<?php
namespace Zh\Jwt\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Zh\Jwt\JwtManager;
use Zh\Jwt\TokenExtractor;

class Optional
{
    protected string $guard;

    public function __construct(string $guard = null)
    {
        $this->guard = $guard ?: '';
    }

    public function process(Request $request, callable $next): Response
    {
        $guard = $this->guard ?: (string) config('plugin.zh.jwt.default_guard', 'frontend');
        $tokenStr = TokenExtractor::fromRequest($request, $guard);
        if ($tokenStr) {
            try {
                $jwt = new JwtManager($guard);
                $token = $jwt->verifyAccess($tokenStr);
                $request->jwt_token = $token;
                $request->jwt_claims = $token->claims()->all();
            } catch (\Throwable $e) {
                // 忽略错误，按未登录处理
            }
        }
        return $next($request);
    }
}