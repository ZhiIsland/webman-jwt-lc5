<?php
namespace Zh\Jwt;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Zh\Jwt\Support\Config;
use Zh\Jwt\Support\Algorithms;
use Zh\Jwt\Exceptions\ConfigException;

class KeyManager
{
    public static function configurationFor(string $guard): Configuration
    {
        $conf = Config::get("guards.{$guard}");
        if (!$conf) {
            throw new ConfigException("JWT guard {$guard} not configured");
        }
        $alg = $conf['algorithm'] ?? 'HS256';
        $signer = Algorithms::for($alg);

        if (Algorithms::isSymmetric($alg)) {
            $secret = $conf['secret'] ?? '';
            if (!$secret) {
                throw new ConfigException("Secret missing for {$alg} guard {$guard}");
            }
            return Configuration::forSymmetricSigner($signer, InMemory::plainText($secret));
        }

        if (Algorithms::isAsymmetric($alg)) {
            $priv = $conf['private_key'] ?? '';
            $pub  = $conf['public_key'] ?? '';
            $pass = $conf['passphrase'] ?? null;
            if (!is_file($priv) || !is_file($pub)) {
                throw new ConfigException("Key files missing for {$alg} guard {$guard}");
            }
            return Configuration::forAsymmetricSigner(
                $signer,
                InMemory::file($priv, (string)($pass ?? '')),
                InMemory::file($pub)
            );
        }

        throw new ConfigException("Unsupported algorithm {$alg} for guard {$guard}");
    }
}