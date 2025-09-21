<?php
namespace Zhiisland\WebmanJwtLc5\Contracts;

interface ClaimsProviderInterface
{
    /**
     * 返回附加 claims，发放 token 时合并到 payload。
     * 注意：不应覆盖保留字段（iss/aud/jti/iat/nbf/exp/sub/guard/type）
     */
    public function provide(string $guard, string $userId, array $currentClaims): array;
}