<?php
namespace Zh\Jwt\Support;

use Zh\Jwt\Contracts\TokenResponseFormatterInterface;

class DefaultTokenResponseFormatter implements TokenResponseFormatterInterface
{
    public function format(array $payload): array
    {
        // 默认原样返回
        return $payload;
    }
}