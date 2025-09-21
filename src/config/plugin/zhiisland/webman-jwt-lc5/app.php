<?php

return [
    'default_guard' => 'frontend',

    // Extractors
    'token_locations' => ['header', 'cookie', 'query'],
    'token_key'       => 'Authorization',
    'token_prefix'    => 'Bearer',
    'cookie_name'     => 'access_token',
    'query_name'      => 'token',

    'refresh_token_locations' => ['header', 'cookie', 'query'],
    'refresh_token_key'       => 'X-Refresh-Token',
    'refresh_cookie_name'     => 'refresh_token',
    'refresh_query_name'      => 'refresh_token',

    // Clock and time
    'leeway' => 10,
    'nbf'    => 0,

    // Features
    'blacklist_enabled' => true,
    'refresh_rotate' => true,
    'refresh_reuse_interval' => 30,
    'refresh_disable' => false,

    'multi_login' => 'per-device', // single | per-device | unlimited
    'max_devices' => 5,

    'client_default' => 'WEB',

    // Sliding refresh middleware
    'sliding' => [
        'enable' => true,
        'access_renew_threshold' => 300,
        'attach' => [
            'type' => 'header', // header | cookie | none
            'access_header'  => 'X-New-Access-Token',
            'refresh_header' => 'X-New-Refresh-Token',
            'cookie_name_access'  => 'access_token',
            'cookie_name_refresh' => 'refresh_token',
            'cookie_options' => [
                'httponly' => true,
                'secure'   => false,
                'samesite' => 'Lax',
            ],
        ],
    ],

    // JWKS 输出（仅 RSA 目前支持自动生成）
    'jwks' => [
        'enable' => false,
        'path' => '/.well-known/jwks.json',
        'cache_ttl' => 300,
        // 仅导出声明了 kid 的 guard
    ],

    // 扩展点
    // - 用户解析：根据 sub 返回用户对象/数组（可用匿名函数或实现接口）
    'user_resolver' => null, // fn(string $guard, string $uid): mixed
    // - Claims Provider 列表：类名数组，每个类实现 ClaimsProviderInterface
    'claims_providers' => [
        // \App\Jwt\Claims\FillUserRoles::class,
    ],
    // - Token 响应格式化器
    'response_formatter' => null, // \Zhiisland\WebmanJwtLc5\Contracts\TokenResponseFormatterInterface::class

    // 异常 => 错误码映射（建议在全局异常处理中使用）
    'error_codes' => [
        'Zhiisland\WebmanJwtLc5\Exceptions\TokenNotProvidedException' => 401010,
        'Zhiisland\WebmanJwtLc5\Exceptions\TokenInvalidException' => 401011,
        'Zhiisland\WebmanJwtLc5\Exceptions\TokenExpiredException' => 401013,
        'Zhiisland\WebmanJwtLc5\Exceptions\TokenBlacklistedException' => 401016,
        'Zhiisland\WebmanJwtLc5\Exceptions\RefreshTokenAlreadyUsedException' => 401026,
        'Zhiisland\WebmanJwtLc5\Exceptions\ScopeViolationException' => 403001,
        'Zhiisland\WebmanJwtLc5\Exceptions\GuardMismatchException' => 401017,
    ],

    'redis' => [
        'prefix' => 'jwt:',
    ],

    'guards' => [
        'frontend' => [
            // 算法：HS256/384/512 | RS256/384/512 | ES256/384/512 | PS256/384/512
            'algorithm' => 'HS256',
            'secret' => 'frontend-secret-long-and-strong',
            'private_key' => null,
            'public_key'  => null,
            'passphrase'  => '',
            'kid' => null,

            'issuer' => 'myapp-frontend',
            'audience' => 'myapp-users',

            'ttl' => 3600,
            'refresh_ttl' => 86400,

            'leeway' => 10,
            'nbf' => 0,

            'required_claims' => ['iss','aud','jti','iat','nbf','exp','sub','guard','type'],
            'custom_claims' => [
                // 'scopes' => ['read']
            ],
        ],
        'admin' => [
            'algorithm' => 'RS256',
            'secret' => null,
            'private_key' => base_path().'/keys/admin-private.pem',
            'public_key'  => base_path().'/keys/admin-public.pem',
            'passphrase'  => '',
            'kid' => 'admin-key-v1',

            'issuer' => 'myapp-admin',
            'audience' => ['myapp-admins'],

            'ttl' => 1800,
            'refresh_ttl' => 43200,

            'leeway' => 5,
            'nbf' => 0,

            'required_claims' => ['iss','aud','jti','iat','nbf','exp','sub','guard','type'],
            'custom_claims' => ['role' => 'admin', 'scopes' => ['admin']],
        ],
    ],
];