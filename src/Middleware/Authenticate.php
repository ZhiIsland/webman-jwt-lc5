<?php
namespace Zhiisland\WebmanJwtLc5\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Zhiisland\WebmanJwtLc5\JwtManager;
use Zhiisland\WebmanJwtLc5\TokenExtractor;
use Zhiisland\WebmanJwtLc5\Exceptions\TokenNotProvidedException;
use Zhiisland\WebmanJwtLc5\Exceptions\ScopeViolationException;

class Authenticate
{
    protected string $guard;
    protected ?array $scopes;

    public function __construct(string $guard = null, array $scopes = null)
    {
        $this->guard = $guard ?: '';
        $this->scopes = $scopes;
    }

    public function process(Request $request, callable $next): Response
    {
        $guard = $this->guard ?: (string) config('plugin.zhiisland.webman-jwt-lc5.app.default_guard', 'frontend');
        $tokenStr = TokenExtractor::fromRequest($request, $guard);

        if (!$tokenStr) {
            throw new TokenNotProvidedException('Token not provided');
        }

        $jwt = new JwtManager($guard);
        $token = $jwt->verifyAccess($tokenStr);

        if ($this->scopes) {
            $tokenScopes = (array) ($token->claims()->get('scopes') ?? []);
            foreach ($this->scopes as $scope) {
                if (!in_array($scope, $tokenScopes, true)) {
                    throw new ScopeViolationException('Insufficient scope');
                }
            }
        }

        $request->jwt_token = $token;
        $request->jwt_claims = $token->claims()->all();

        return $next($request);
    }
}