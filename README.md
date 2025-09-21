# Webman JWT 插件（lcobucci/jwt v5）— 增强版

本插件基于 lcobucci/jwt v5 + lcobucci/clock v3，为 Webman 提供完善、可扩展、可观测的 JWT 认证能力。设计上参考并融合了社区优秀实现（如 [yzh52521/webman-jwt-auth](https://github.com/yzh52521/webman-jwt-auth)、[Tinywan/webman-jwt](https://github.com/Tinywan/webman-jwt)），并拥抱异常（验证错误直接抛出），便于全局统一处理。

- 文档适配版本：v0.1.2（相对 v0.1.0/0.1.1 增强了链式/静态 API、自动从请求提取 token、JWKS、PS* 算法、扩展点等）

---

## 目录

- 特性
- 快速开始
- 安装
- 配置详解
- 使用指南
    - 登录颁发
    - 保护路由与中间件
    - 刷新与登出
    - 获取用户与 Claims
    - 链式与静态 API
    - 无需显式传 token（自动从请求提取）
    - JWKS（可选）
- 高级能力
    - 单点登录策略（SSO）
    - 刷新策略与滑动续期
    - 终端/设备维度下线
    - 一次性覆盖 TTL
- 扩展点
- 异常一览与错误码映射
- 安全建议
- 迁移指引
- 版本

---

## 特性

- 多 guard（前台/后台等），独立密钥、TTL、Claims、校验策略
- 双 Token（access/refresh），支持刷新轮换（Rotation）与防重放（Reuse Window）
- SSO 策略：single / per-device / unlimited（可限制最大设备数，淘汰最旧设备）
- 黑名单（jti 级），退出、强制下线立刻生效
- Token 提取：Header/Cookie/Query，可独立配置 refresh 提取
- 算法支持：HS256/384/512、RS256/384/512、ES256/384/512、PS256/384/512（RS/PS 可导出 JWKS）
- kid 支持：Header 写入 kid，便于密钥轮换
- 时间约束：SignedWith + StrictValidAt/LooseValidAt + leeway + nbf
- 终端与设备维度：client + device 组合，按终端/设备踢人
- 滑动续期中间件：access 剩余寿命低于阈值时自动刷新，回写到 Header/Cookie
- 存储抽象（默认 Redis），可替换实现
- 扩展点：Claims Provider、User Resolver、Token 响应格式化器
- 静态/链式 API：快速发放、验证、刷新、获取当前用户/Claims、按终端下线
- 自动从请求提取 token：大部分操作可零参数调用（默认从当前请求读取）

---

## 快速开始

1) 安装
```bash
composer require zhiisland/webman-jwt-lc5
```

2) 配置密钥与 guard（编辑 config/plugin/zh/jwt/app.php）
- HS：设置 guards.*.algorithm=HS256|384|512 和 secret
- RS/PS/ES：设置 private_key、public_key、passphrase，可选 kid 支持轮换
- issuer、audience（支持数组）、ttl/refresh_ttl（秒）、required_claims

生成 RS256 密钥对：
```bash
openssl genrsa -out admin-private.pem 2048
openssl rsa -in admin-private.pem -pubout -out admin-public.pem
```

3) 登录发放
```php
use Zhiisland\WebmanJwtLc5\JwtManager;

$jwt = new JwtManager('frontend');
$tokens = $jwt->issueTokens('10001', ['scopes' => ['read','write'], 'client' => 'WEB'], 'web-device-1');
// => ['access_token','refresh_token','expires_in','refresh_expires_in','token_type']
```

或（静态）：
```php
use Zhiisland\WebmanJwtLc5\JwtToken;

$tokens = JwtToken::generateToken([
  'id' => 2022,
  'name' => 'Alice',
  'client' => Zhiisland\WebmanJwtLc5\JwtToken::TOKEN_CLIENT_MOBILE,
  'access_exp' => 7200,
], 'frontend', Zhiisland\WebmanJwtLc5\JwtToken::TOKEN_CLIENT_MOBILE, 'iphone-15-pro');
```

4) 保护路由
```php
->middleware([\Zhiisland\WebmanJwtLc5\Middleware\Authenticate::class], ['guard' => 'frontend'])
// 可选：Authenticate 之后加滑动续期
->middleware([\Zhiisland\WebmanJwtLc5\Middleware\SlidingRefresh::class], ['guard' => 'frontend'])
```

---

## 安装

Webman 会自动加载 `config/plugin/zh/jwt/app.php`。

克隆到现有项目时请拷贝：
- `config/plugin/zh/jwt/app.php`
- 源码位于 `src/`，命名空间 `Zhiisland\WebmanJwtLc5\*`

---

## 配置详解

关键键位于 `config/plugin/zh/jwt/app.php`：

- default_guard：默认 guard 名
- token_locations：['header','cookie','query'] 提取 access 的优先级
- token_key/token_prefix：请求头键名与前缀（默认 Authorization: Bearer xxx）
- cookie_name/query_name：承载 access 的 cookie/query 键
- refresh_token_locations/refresh_token_key/...：refresh 的提取配置
- leeway（秒）：时钟偏差窗口；nbf（秒）：多少秒后生效
- blacklist_enabled：黑名单总开关
- refresh_rotate/refresh_reuse_interval/refresh_disable：刷新策略
- multi_login/max_devices：SSO 策略
- client_default：默认终端（WEB/MOBILE/WECHAT/ADMIN/API/OTHER）
- sliding：滑动续期配置，低剩余寿命时自动刷新并将新 token 写入响应
- jwks：开启后提供 RS/PS 公钥的 JWKS 输出
- error_codes：异常类 => 错误码映射
- guards：多 guard 配置（algorithm/secret/keys/kid/issuer/audience/ttl/...）

---

## 使用指南

### 登录颁发
见“快速开始第 3 点”。

### 保护路由与中间件
- Authenticate：强制登录
- Optional：可选登录（携带 token 则识别，失败忽略）
- RequireScopes：附加 scope 校验
- SlidingRefresh：access 剩余寿命低于阈值时自动刷新

示例：
```php
->middleware([\Zhiisland\WebmanJwtLc5\Middleware\Authenticate::class], ['guard' => 'frontend'])
->middleware([\Zhiisland\WebmanJwtLc5\Middleware\SlidingRefresh::class], ['guard' => 'frontend'])
```

### 刷新与登出
```php
// 主动刷新（手动传 refresh）
(new Zhiisland\WebmanJwtLc5\JwtManager('frontend'))->refresh($refreshToken);

// 自动从请求提取 refresh（详见下节“无需显式传 token”）
$new = Zhiisland\WebmanJwtLc5\JwtToken::refreshToken();

// 登出（拉黑当前 access），并按终端清理
Zhiisland\WebmanJwtLc5\JwtToken::clear('frontend', Zhiisland\WebmanJwtLc5\JwtToken::TOKEN_CLIENT_WEB);
```

### 获取当前用户与 Claims
```php
$uid    = Zhiisland\WebmanJwtLc5\JwtToken::getCurrentId();
$claims = Zhiisland\WebmanJwtLc5\JwtToken::getExtend();
$user   = Zhiisland\WebmanJwtLc5\JwtToken::getUser(); // 需配置 user_resolver
```

### 链式与静态 API

- 链式
```php
use Zhiisland\WebmanJwtLc5\Jwt;

$tokens = Jwt::make('frontend')
  ->client('WEB')
  ->device('web-1')
  ->claims(['scopes' => ['read']])
  ->ttl(3600)          // 本次 access = 3600 秒
  ->refreshTtl(86400)  // 本次 refresh = 1 天
  ->issue('10001');

$plain = Jwt::make('frontend')->verifyAccess();
$new   = Jwt::make('frontend')->refresh();
Jwt::make('frontend')->invalidate();
```

- 静态
```php
use Zhiisland\WebmanJwtLc5\Jwt;

$tokens = Jwt::issue('frontend', '10001', ['client' => 'WEB'], 'web-1');
$token  = Jwt::verify('frontend', $jwt);
$new    = Jwt::refresh('frontend', $refreshJwt);
Jwt::invalidate('frontend', $jwt);

// 自动从请求提取
$token = Jwt::verifyFromRequest('frontend');
$new   = Jwt::refreshFromRequest('frontend');
Jwt::invalidateFromRequest('frontend');
```

### 无需显式传 token（自动从请求提取）

- TokenExtractor::fromCurrentRequest($guard) / fromCurrentRequestRefresh($guard)
- JwtFluent/Jwt 的 verifyAccess/refresh/invalidate 在未传参时自动提取
- 工具类（借鉴 meta\utils\JWTUtil）
```php
use Zhiisland\WebmanJwtLc5\Utils\JWTUtil;

$claims = JWTUtil::getParserData('frontend'); // 解析 claims（不做签名/时间校验）
$plain  = JWTUtil::verify('frontend');        // 验证并返回 Plain Token
$new    = JWTUtil::refresh('frontend');       // 刷新（需请求带 refresh）
JWTUtil::invalidate('frontend');              // 拉黑当前 access
```

提取优先级与键名由配置控制：
- access：token_locations + token_key/token_prefix + cookie_name + query_name
- refresh：refresh_token_locations + refresh_token_key + refresh_cookie_name + refresh_query_name

### JWKS（可选）

开启后导出 RS/PS guard 的公钥，便于其他服务验证签名。

配置：
```php
'jwks' => ['enable' => true, 'path' => '/.well-known/jwks.json']
```
路由：
```php
use Webman\Route;
Route::get('/.well-known/jwks.json', [\Zhiisland\WebmanJwtLc5\Controller\JwksController::class, 'index']);
```

要求 guard 配置有 `kid` 与 `public_key`。

---

## 高级能力

- 单点登录策略（SSO）
    - single：同一用户只保留最新会话（全终端下线）
    - per-device：按 channelKey（client:device）维持会话，可限制最大设备数
    - unlimited：不限制

- 刷新策略与滑动续期
    - refresh_rotate：刷新轮换，旧 refresh 一次一用
    - refresh_reuse_interval：弱网重复提交容忍窗口
    - refresh_disable：禁用刷新能力
    - SlidingRefresh：access 剩余寿命低于阈值自动刷新；新 token 可回写到 Header 或 Cookie

- 终端/设备维度下线
    - `invalidateUserByClient($userId, $client)` 一键踢出该终端所有会话
    - `invalidateUser($userId, "{$client}:{$deviceId}")` 指定终端+设备踢出

- 一次性覆盖 TTL
    - 登录发放时在 claims 中传入 `access_exp` / `refresh_exp`

---

## 扩展点

- Claims Provider：发放时动态补充 claims
    - 实现 `Zhiisland\WebmanJwtLc5\Contracts\ClaimsProviderInterface`
    - 在配置 `claims_providers` 中注册类名
- User Resolver：按 sub 获取用户对象/数组
    - 配置 `user_resolver` 为匿名函数或实现 `Zhiisland\WebmanJwtLc5\Contracts\UserResolverInterface` 的类
- Token 响应格式化
    - 实现 `Zhiisland\WebmanJwtLc5\Contracts\TokenResponseFormatterInterface`
    - 配置 `response_formatter` 替换默认返回结构
- 存储替换
    - 实现 `Zhiisland\WebmanJwtLc5\Contracts\JwtStorageInterface` 并注入到 `JwtManager` 构造

---

## 异常一览与错误码映射

- Zhiisland\WebmanJwtLc5\Exceptions\ConfigException
- Zhiisland\WebmanJwtLc5\Exceptions\TokenNotProvidedException
- Zhiisland\WebmanJwtLc5\Exceptions\TokenInvalidException
- Zhiisland\WebmanJwtLc5\Exceptions\TokenExpiredException
- Zhiisland\WebmanJwtLc5\Exceptions\TokenBlacklistedException
- Zhiisland\WebmanJwtLc5\Exceptions\RefreshTokenAlreadyUsedException
- Zhiisland\WebmanJwtLc5\Exceptions\ScopeViolationException
- Zhiisland\WebmanJwtLc5\Exceptions\GuardMismatchException

建议在全局异常处理中读取 `config('plugin.zh.jwt.error_codes')`，将异常映射为统一错误码与响应体。

---

## 安全建议

- 生产优先使用 RS/PS（推荐 RS256 或 PS256），启用 kid + JWKS 便于多服务验证与轮换
- 合理设置 `leeway`（小于几分钟）与 `nbf`（按需延迟可用时间）
- 使用 Cookie 时建议 HttpOnly + SameSite=Lax；跨域需 SameSite=None + Secure
- 定期轮换私钥/secret；启用刷新轮换可缩小泄露窗口
- Scope 只做粗粒度，业务侧务必继续做细粒度鉴权

---

## 迁移指引

- 从 v0.1.0 升级：
    - 新增 PS256/384/512
    - 新增 JWKS 输出（可选）
    - 新增 Claims Provider、User Resolver、Response Formatter
    - 新增静态 API：getUser()/clear(client)
    - 新增 SlidingRefresh 中间件
    - 支持 audience 数组、kid、nbf
    - 配置新增多个键；旧配置仍兼容基本场景

- 从 v0.1.1 升级：
    - 新增：自动从当前请求提取 token 的静态/链式便捷方法
    - 新增：工具类 JWTUtil（getToken/getParserData/verify/refresh/invalidate）
    - 文档重写与结构优化

---

## 版本

- v0.1.0 初始发布
- v0.1.1 增强：算法家族扩展、kid/JWKS、滑动续期、扩展点、静态 API 完善
- v0.1.2 增强：自动从请求提取 token、链式与静态零参操作、工具类 JWTUtil、文档重写