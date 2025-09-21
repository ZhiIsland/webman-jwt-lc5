<?php
namespace Zh\Jwt\Contracts;

interface TokenResponseFormatterInterface
{
    /**
     * 格式化 issueTokens/refresh 的返回结果
     */
    public function format(array $payload): array;
}