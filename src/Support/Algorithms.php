<?php
namespace Zh\Jwt\Support;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as PS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as PS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as PS512;

final class Algorithms
{
    public static function for(string $alg): Signer
    {
        $upper = strtoupper($alg);
        return match ($upper) {
            'HS256' => new HS256(),
            'HS384' => new HS384(),
            'HS512' => new HS512(),
            'RS256' => new RS256(),
            'RS384' => new RS384(),
            'RS512' => new RS512(),
            'ES256' => new ES256(),
            'ES384' => new ES384(),
            'ES512' => new ES512(),
            'PS256' => new PS256(),
            'PS384' => new PS384(),
            'PS512' => new PS512(),
            default => throw new \InvalidArgumentException("Unsupported algorithm: {$alg}"),
        };
    }

    public static function isSymmetric(string $alg): bool
    {
        return str_starts_with(strtoupper($alg), 'HS');
    }

    public static function isAsymmetric(string $alg): bool
    {
        $a = strtoupper($alg);
        return str_starts_with($a, 'RS') || str_starts_with($a, 'ES') || str_starts_with($a, 'PS');
    }
}