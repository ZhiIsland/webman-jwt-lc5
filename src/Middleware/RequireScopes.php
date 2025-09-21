<?php
namespace Zhiisland\WebmanJwtLc5\Middleware;

use Webman\Http\Request;
use Webman\Http\Response;
use Zhiisland\WebmanJwtLc5\Exceptions\ScopeViolationException;

class RequireScopes
{
    protected array $scopes;

    public function __construct(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function process(Request $request, callable $next): Response
    {
        $claims = $request->jwt_claims ?? [];
        $tokenScopes = (array) ($claims['scopes'] ?? []);
        foreach ($this->scopes as $scope) {
            if (!in_array($scope, $tokenScopes, true)) {
                throw new ScopeViolationException('Insufficient scope');
            }
        }
        return $next($request);
    }
}