<?php
namespace Zhiisland\WebmanJwtLc5\Support;

use Zhiisland\WebmanJwtLc5\Contracts\TokenResponseFormatterInterface;

class DefaultTokenResponseFormatter implements TokenResponseFormatterInterface
{
    public function format(array $payload): array
    {
        // 默认原样返回
        return $payload;
    }
}