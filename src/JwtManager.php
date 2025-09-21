<?php
namespace Zhiisland\WebmanJwtLc5;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token\Plain as PlainToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Zhiisland\WebmanJwtLc5\Contracts\ClaimsProviderInterface;
use Zhiisland\WebmanJwtLc5\Contracts\JwtStorageInterface;
use Zhiisland\WebmanJwtLc5\Contracts\TokenResponseFormatterInterface;
use Zhiisland\WebmanJwtLc5\Exceptions\GuardMismatchException;
use Zhiisland\WebmanJwtLc5\Exceptions\JwtException;
use Zhiisland\WebmanJwtLc5\Exceptions\RefreshTokenAlreadyUsedException;
use Zhiisland\WebmanJwtLc5\Exceptions\TokenBlacklistedException;
use Zhiisland\WebmanJwtLc5\Exceptions\TokenExpiredException;
use Zhiisland\WebmanJwtLc5\Exceptions\TokenInvalidException;
use Zhiisland\WebmanJwtLc5\Support\Config;
use Zhiisland\WebmanJwtLc5\Support\DefaultTokenResponseFormatter;
use Zhiisland\WebmanJwtLc5\Storage\RedisStorage;

class JwtManager
{
    protected string $guard;
    protected array $conf;
    protected Configuration $config;
    protected JwtStorageInterface $storage;

    public function __construct(?string $guard = null, ?JwtStorageInterface $storage = null)
    {
        $this->guard = $guard ?: (string) Config::get('default_guard', 'frontend');
        $this->conf  = Config::get("guards.{$this->guard}", []);
        if (!$this->conf) {
            throw new JwtException("Guard {$this->guard} not configured");
        }
        $this->config  = KeyManager::configurationFor($this->guard);
        $this->storage = $storage ?: new RedisStorage();
    }

    public static function uuid(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    protected function applyClaimsProviders(string $userId, array $claims): array
    {
        $providers = (array) Config::get('claims_providers', []);
        foreach ($providers as $cls) {
            if (is_string($cls) && class_exists($cls)) {
                $p = new $cls();
                if ($p instanceof ClaimsProviderInterface) {
                    $extra = $p->provide($this->guard, $userId, $claims);
                    if (!empty($extra)) {
                        // 防止覆盖保留字段，调用方自行控制
                        $claims = array_merge($claims, $extra);
                    }
                }
            }
        }
        return $claims;
    }

    protected function formatResponse(array $res): array
    {
        $fmt = Config::get('response_formatter');
        if (is_string($fmt) && class_exists($fmt)) {
            $f = new $fmt();
            if ($f instanceof TokenResponseFormatterInterface) {
                return $f->format($res);
            }
        }
        return (new DefaultTokenResponseFormatter())->format($res);
    }

    public function issueTokens(string $userId, array $claims = [], ?string $deviceId = null): array
    {
        if (Config::get('refresh_disable', false)) {
            // 允许仅发放 access
        }

        $now = new DateTimeImmutable();
        $leeway   = (int) ($this->conf['leeway'] ?? Config::get('leeway', 0));
        $nbfOffset= (int) ($this->conf['nbf'] ?? Config::get('nbf', 0));

        $claims = $this->applyClaimsProviders($userId, $claims);

        $accessTtl  = (int)($claims['access_exp']  ?? $this->conf['ttl']         ?? 3600);
        $refreshTtl = (int)($claims['refresh_exp'] ?? $this->conf['refresh_ttl']  ?? 86400);

        $issuer = $this->conf['issuer'] ?? null;
        $aud    = $this->conf['audience'] ?? null; // string|array
        $kid    = $this->conf['kid'] ?? null;

        $jtiAccess  = self::uuid();
        $jtiRefresh = self::uuid();

        // Access
        $ab = $this->config->builder()
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($nbfOffset > 0 ? $now->modify("+{$nbfOffset} seconds") : $now->modify("+{$leeway} seconds"))
            ->identifiedBy($jtiAccess)
            ->relatedTo($userId)
            ->withClaim('guard', $this->guard)
            ->withClaim('type', 'access')
            ->expiresAt($now->modify("+{$accessTtl} seconds"));

        if ($issuer) $ab = $ab->issuedBy($issuer);
        if ($aud) {
            foreach ((array)$aud as $a) {
                $ab = $ab->permittedFor((string)$a);
            }
        }
        if ($kid) $ab = $ab->withHeader('kid', $kid);

        foreach (($this->conf['custom_claims'] ?? []) as $k => $v) {
            $ab = $ab->withClaim($k, $v);
        }
        foreach ($claims as $k => $v) {
            $ab = $ab->withClaim($k, $v);
        }
        if ($deviceId) {
            $ab = $ab->withClaim('device_id', $deviceId);
        }

        /** @var PlainToken $access */
        $access = $ab->getToken($this->config->signer(), $this->config->signingKey());

        // Refresh
        $refreshReturn = null;
        if (!Config::get('refresh_disable', false)) {
            $rb = $this->config->builder()
                ->issuedAt($now)
                ->canOnlyBeUsedAfter($nbfOffset > 0 ? $now->modify("+{$nbfOffset} seconds") : $now->modify("+{$leeway} seconds"))
                ->identifiedBy($jtiRefresh)
                ->relatedTo($userId)
                ->withClaim('guard', $this->guard)
                ->withClaim('type', 'refresh')
                ->expiresAt($now->modify("+{$refreshTtl} seconds"));

            if ($issuer) $rb = $rb->issuedBy($issuer);
            if ($aud) {
                foreach ((array)$aud as $a) {
                    $rb = $rb->permittedFor((string)$a);
                }
            }
            if ($kid) $rb = $rb->withHeader('kid', $kid);
            if ($deviceId) $rb = $rb->withClaim('device_id', $deviceId);
            if (isset($claims['client'])) $rb = $rb->withClaim('client', (string)$claims['client']);

            /** @var PlainToken $refresh */
            $refresh = $rb->getToken($this->config->signer(), $this->config->signingKey());
            $refreshReturn = $refresh;
        }

        // SSO
        $client = isset($claims['client']) ? (string)$claims['client'] : (string) Config::get('client_default', 'WEB');
        $channelKey = $deviceId ? "{$client}:{$deviceId}" : $client;
        $this->applySsoPolicy($userId, $channelKey, $access, $refreshReturn);

        $res = [
            'token_type' => 'Bearer',
            'access_token' => $access->toString(),
            'expires_in' => $accessTtl,
        ];
        if ($refreshReturn) {
            $res['refresh_token'] = $refreshReturn->toString();
            $res['refresh_expires_in'] = $refreshTtl;
        }

        return $this->formatResponse($res);
    }

    protected function applySsoPolicy(string $userId, string $channelKey, PlainToken $access, ?PlainToken $refresh): void
    {
        $policy = (string) Config::get('multi_login', 'per-device');
        $maxDevices = (int) Config::get('max_devices', 5);
        $blacklistEnabled = (bool) Config::get('blacklist_enabled', true);

        $ttl = max(1, $this->expLeft($access));
        if ($refresh) {
            $ttl = max($ttl, max(1, $this->expLeft($refresh)));
        }

        if ($policy === 'single') {
            $active = $this->storage->getActiveTokens($this->guard, $userId);
            foreach ($active as $dev => $jti) {
                if ($blacklistEnabled) {
                    $this->storage->blacklist($this->guard, $jti, $ttl);
                }
            }
            $this->storage->bindActiveToken($this->guard, $userId, $channelKey, $access->claims()->get('jti'), $ttl);
            return;
        }

        if ($policy === 'per-device') {
            $active = $this->storage->getActiveTokens($this->guard, $userId);
            if (isset($active[$channelKey]) && $blacklistEnabled) {
                $this->storage->blacklist($this->guard, $active[$channelKey], $ttl);
            }
            $maybePop = $this->storage->pushDeviceAndMaybePop($this->guard, $userId, $channelKey, $maxDevices);
            if ($maybePop && isset($active[$maybePop]) && $blacklistEnabled) {
                $this->storage->blacklist($this->guard, $active[$maybePop], $ttl);
                $this->storage->unbindActiveToken($this->guard, $userId, $maybePop);
            }
            $this->storage->bindActiveToken($this->guard, $userId, $channelKey, $access->claims()->get('jti'), $ttl);
            return;
        }

        if ($policy === 'unlimited') {
            $this->storage->bindActiveToken($this->guard, $userId, $channelKey, $access->claims()->get('jti'), $ttl);
        }
    }

    protected function expLeft(PlainToken $token): int
    {
        $exp = $token->claims()->get('exp');
        if ($exp instanceof \DateTimeImmutable) {
            return $exp->getTimestamp() - time();
        }
        if (is_int($exp)) {
            return $exp - time();
        }
        return 0;
    }

    public function parse(string $jwt): PlainToken
    {
        $token = $this->config->parser()->parse($jwt);
        if (!$token instanceof PlainToken) {
            throw new TokenInvalidException('Unsupported token type');
        }
        return $token;
    }

    protected function timeConstraint(): ?object
    {
        $leeway = (int) ($this->conf['leeway'] ?? Config::get('leeway', 0));
        $clock = SystemClock::fromUTC();

        if (class_exists(\Lcobucci\JWT\Validation\Constraint\StrictValidAt::class)) {
            $di = $leeway > 0 ? new DateInterval('PT'.$leeway.'S') : null;
            return new \Lcobucci\JWT\Validation\Constraint\StrictValidAt($clock, $di);
        }
        if (class_exists(\Lcobucci\JWT\Validation\Constraint\LooseValidAt::class)) {
            $di = $leeway > 0 ? new DateInterval('PT'.$leeway.'S') : null;
            return new \Lcobucci\JWT\Validation\Constraint\LooseValidAt($clock, $di);
        }
        if (class_exists(\Lcobucci\JWT\Validation\Constraint\ValidAt::class)) {
            return new \Lcobucci\JWT\Validation\Constraint\ValidAt($clock, $leeway);
        }
        return null;
    }

    public function validate(PlainToken $token, bool $allowExpired = false): void
    {
        $constraints = [];
        $constraints[] = new SignedWith($this->config->signer(), $this->config->verificationKey());

        if (!empty($this->conf['issuer'])) {
            $constraints[] = new IssuedBy($this->conf['issuer']);
        }
        if (!empty($this->conf['audience'])) {
            foreach ((array)$this->conf['audience'] as $a) {
                $constraints[] = new PermittedFor((string)$a);
            }
        }

        if (!$allowExpired) {
            $timeConstraint = $this->timeConstraint();
            if ($timeConstraint) {
                $constraints[] = $timeConstraint;
            }
        }

        try {
            if (!empty($constraints)) {
                $this->config->validator()->assert($token, ...$constraints);
            }

            $required = $this->conf['required_claims'] ?? [];
            $claims = $token->claims();
            foreach ($required as $rc) {
                if (!$claims->has($rc)) {
                    throw new TokenInvalidException("Required claim missing: {$rc}");
                }
            }

            if (($claims->get('guard') ?? null) !== $this->guard) {
                throw new GuardMismatchException('Guard mismatch');
            }
        } catch (\Lcobucci\JWT\Validation\RequiredConstraintsViolated $e) {
            $nowTs = time();
            $exp = $token->claims()->has('exp') ? $token->claims()->get('exp') : null;
            if ($exp instanceof \DateTimeImmutable && $exp->getTimestamp() <= $nowTs) {
                throw new TokenExpiredException('Token expired', 0, $e);
            }
            if (is_int($exp) && $exp <= $nowTs) {
                throw new TokenExpiredException('Token expired', 0, $e);
            }
            throw new TokenInvalidException('Token validation failed: '.$e->getMessage(), 0, $e);
        }
    }

    public function assertNotBlacklisted(PlainToken $token): void
    {
        if (!Config::get('blacklist_enabled', true)) {
            return;
        }
        $jti = (string) $token->claims()->get('jti');
        if ($this->storage->isBlacklisted($this->guard, $jti)) {
            throw new TokenBlacklistedException('Token blacklisted');
        }
    }

    public function verifyAccess(string $jwt): PlainToken
    {
        $token = $this->parse($jwt);
        $this->validate($token, false);
        if (($token->claims()->get('type') ?? '') !== 'access') {
            throw new TokenInvalidException('Not an access token');
        }
        $this->assertNotBlacklisted($token);
        return $token;
    }

    public function refresh(string $refreshTokenString): array
    {
        if (Config::get('refresh_disable', false)) {
            throw new TokenInvalidException('Refresh is disabled by config');
        }

        $token = $this->parse($refreshTokenString);
        $this->validate($token, false);
        if (($token->claims()->get('type') ?? '') !== 'refresh') {
            throw new TokenInvalidException('Not a refresh token');
        }
        $this->assertNotBlacklisted($token);

        $userId = (string) $token->claims()->get('sub');
        $deviceId = $token->claims()->has('device_id') ? (string)$token->claims()->get('device_id') : null;
        $client = $token->claims()->has('client') ? (string)$token->claims()->get('client') : (string) Config::get('client_default', 'WEB');
        $refreshJti = (string) $token->claims()->get('jti');
        $guard = (string) $token->claims()->get('guard');

        $rotate = (bool) Config::get('refresh_rotate', true);
        $reuseInterval = (int) Config::get('refresh_reuse_interval', 30);

        if ($rotate) {
            if ($this->storage->isRefreshUsed($guard, $refreshJti)) {
                throw new \Zhiisland\WebmanJwtLc5\Exceptions\RefreshTokenAlreadyUsedException('Refresh token already used');
            }
            $ttl = max(1, $this->expLeft($token) + $reuseInterval);
            $this->storage->markRefreshUsed($guard, $refreshJti, $ttl);
        }

        $newClaims = ['client' => $client];
        $new = $this->issueTokens($userId, $newClaims, $deviceId);

        if (Config::get('blacklist_enabled', true) && $rotate) {
            $ttlBl = max(1, $this->expLeft($token));
            $this->storage->blacklist($guard, $refreshJti, $ttlBl);
        }

        return $new['refresh_token'] ?? null ? $this->formatResponse($new) : $this->formatResponse([
            'token_type'   => 'Bearer',
            'access_token' => $new['access_token'],
            'expires_in'   => $new['expires_in'],
            'refresh_token' => $refreshTokenString,
            'refresh_expires_in' => max(1, $this->expLeft($token)),
        ]);
    }

    public function invalidate(string $jwtString): void
    {
        if (!Config::get('blacklist_enabled', true)) {
            return;
        }
        $token = $this->parse($jwtString);
        $this->validate($token, true);
        $jti = (string) $token->claims()->get('jti');
        $ttl = max(1, $this->expLeft($token));
        $this->storage->blacklist($this->guard, $jti, $ttl);
    }

    public function invalidateUser(string $userId, ?string $channelKey = null): void
    {
        if (!Config::get('blacklist_enabled', true)) {
            return;
        }
        $active = $this->storage->getActiveTokens($this->guard, $userId);
        foreach ($active as $dev => $jti) {
            if ($channelKey !== null && $dev !== $channelKey) {
                continue;
            }
            $this->storage->blacklist($this->guard, $jti, 7200);
            if ($channelKey !== null) {
                $this->storage->unbindActiveToken($this->guard, $userId, $channelKey);
            }
        }
    }

    public function invalidateUserByClient(string $userId, string $client): void
    {
        $active = $this->storage->getActiveTokens($this->guard, $userId);
        foreach ($active as $dev => $jti) {
            if (str_starts_with($dev, $client)) {
                $this->storage->blacklist($this->guard, $jti, 7200);
                $this->storage->unbindActiveToken($this->guard, $userId, $dev);
            }
        }
    }
}