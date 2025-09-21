<?php
namespace Zh\Jwt\Controller;

use Webman\Http\Request;
use Webman\Http\Response;
use Zh\Jwt\Support\Config;
use Zh\Jwt\Support\Jwk;

class JwksController
{
    public function index(Request $request): Response
    {
        if (!Config::get('jwks.enable', false)) {
            return new Response(404, ['Content-Type' => 'application/json'], json_encode(['error' => 'JWKS disabled']));
        }

        $keys = [];
        $guards = Config::get('guards', []);
        foreach ($guards as $guard => $conf) {
            $alg = strtoupper($conf['algorithm'] ?? 'HS256');
            $kid = $conf['kid'] ?? null;

            // 仅对 RS/PS 系列自动导出 JWK
            if (in_array(substr($alg, 0, 2), ['RS', 'PS'], true)) {
                $pubPath = $conf['public_key'] ?? null;
                if ($pubPath && is_file($pubPath)) {
                    $pem = file_get_contents($pubPath) ?: '';
                    $jwk = Jwk::fromRsaPublicKeyPem($pem, $kid, $alg);
                    if ($jwk) {
                        $keys[] = $jwk;
                    }
                }
            }
        }

        $body = json_encode(['keys' => $keys], JSON_UNESCAPED_SLASHES);
        return new Response(200, ['Content-Type' => 'application/json'], $body);
    }
}