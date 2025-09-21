<?php
namespace Zhiisland\WebmanJwtLc5\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Zhiisland\WebmanJwtLc5\JwtManager;
use Zhiisland\WebmanJwtLc5\TokenExtractor;
use Zhiisland\WebmanJwtLc5\Support\Config;

class SlidingRefresh
{
    protected string $guard;

    public function __construct(string $guard = null)
    {
        $this->guard = $guard ?: '';
    }

    public function process(Request $request, callable $next): Response
    {
        $guard = $this->guard ?: (string) config('plugin.zhiisland.webman-jwt-lc5.app.default_guard', 'frontend');
        $sliding = Config::get('sliding', []);
        if (empty($sliding['enable'])) {
            return $next($request);
        }

        // 没有 access 或者 refresh 就直接放行
        $accessStr = TokenExtractor::fromRequest($request, $guard);
        if (!$accessStr) {
            return $next($request);
        }

        $jm = new JwtManager($guard);
        try {
            $token = $jm->verifyAccess($accessStr);
        } catch (\Throwable $e) {
            // access 已失效则不做滑动续期，交由上游 Authenticate 处理异常
            return $next($request);
        }

        // 低于阈值触发续期
        $exp = $token->claims()->get('exp');
        $left = is_int($exp) ? $exp - time() : ($exp instanceof \DateTimeImmutable ? $exp->getTimestamp() - time() : PHP_INT_MAX);
        $threshold = (int) ($sliding['access_renew_threshold'] ?? 300);

        $response = $next($request);

        if ($left > 0 && $left <= $threshold && !Config::get('refresh_disable', false)) {
            $refreshStr = TokenExtractor::fromRequestRefresh($request, $guard);
            if ($refreshStr) {
                try {
                    $new = $jm->refresh($refreshStr);
                    $attach = $sliding['attach'] ?? ['type' => 'header'];
                    $type = $attach['type'] ?? 'header';
                    if ($type === 'header') {
                        $response->header($attach['access_header'] ?? 'X-New-Access-Token', $new['access_token'] ?? '');
                        if (!empty($new['refresh_token'])) {
                            $response->header($attach['refresh_header'] ?? 'X-New-Refresh-Token', $new['refresh_token']);
                        }
                    } elseif ($type === 'cookie') {
                        $co = $attach['cookie_options'] ?? ['httponly' => true, 'secure' => false, 'samesite' => 'Lax'];
                        $response->cookie($attach['cookie_name_access'] ?? 'access_token', $new['access_token'] ?? '', 0, '/', '', $co['secure'] ?? false, $co['httponly'] ?? true, $co['samesite'] ?? 'Lax');
                        if (!empty($new['refresh_token'])) {
                            $response->cookie($attach['cookie_name_refresh'] ?? 'refresh_token', $new['refresh_token'], 0, '/', '', $co['secure'] ?? false, $co['httponly'] ?? true, $co['samesite'] ?? 'Lax');
                        }
                    }
                } catch (\Throwable $e) {
                    // 刷新失败不影响原响应
                }
            }
        }

        return $response;
    }
}