<?php
namespace Zh\Jwt\Contracts;

interface UserResolverInterface
{
    /**
     * 根据 sub（userId）返回用户对象/数组，未找到返回 null
     */
    public function resolve(string $guard, string $userId);
}