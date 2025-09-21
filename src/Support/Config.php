<?php
namespace Zhiisland\WebmanJwtLc5\Support;

class Config
{
    public static function get(string $key = '', $default = null)
    {
        $prefix = 'plugin.zhiisland.webman-jwt-lc5.app';
        if ($key === '' || $key === null) {
            return config($prefix, $default);
        }
        return config($prefix.'.'.$key, $default);
    }
}