<?php
namespace Zh\Jwt\Support;

class Config
{
    public static function get(string $key = '', $default = null)
    {
        $prefix = 'plugin.zh.jwt';
        if ($key === '' || $key === null) {
            return config($prefix, $default);
        }
        return config($prefix.'.'.$key, $default);
    }
}