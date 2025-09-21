<?php
namespace Zh\Jwt\Support;

final class Jwk
{
    // base64url 编码
    public static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /**
     * 仅 RSA 公钥 => JWK
     */
    public static function fromRsaPublicKeyPem(string $pem, string $kid = null, string $alg = 'RS256'): ?array
    {
        $res = openssl_pkey_get_public($pem);
        if (!$res) {
            return null;
        }
        $details = openssl_pkey_get_details($res);
        if (!$details || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA) {
            return null;
        }
        $n = $details['rsa']['n'] ?? null;
        $e = $details['rsa']['e'] ?? null;
        if (!$n || !$e) {
            return null;
        }
        return [
            'kty' => 'RSA',
            'alg' => $alg,
            'use' => 'sig',
            'kid' => $kid,
            'n'   => self::b64u($n),
            'e'   => self::b64u($e),
        ];
    }
}