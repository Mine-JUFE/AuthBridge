# AuthBridge

AuthBridge 是一个面向 CAS 单点登录场景的认证桥接服务：
- 作为 CAS Service 接收并校验 ticket
- 基于应用维度生成 JWT（AES 或 ECC）
- 支持 callback 回调模式和 token 展示页模式
- 支持子路径部署（例如 `/authbridge`）

本文档为生产上线版操作手册。

## 1. 运行环境

- Node.js >= 16
- npm >= 7
- Redis（建议生产启用）
- 可访问 CAS 域名（默认 `CAS_BASE_URL`）

安装依赖：

```shell
npm install
```

## 2. 初始化配置（必做）

Windows：

```shell
copy .env.example .env
copy applist.template.json applist.json
```

Linux/macOS：

```shell
cp .env.example .env
cp applist.template.json applist.json
```

可选（仅本地开发回退）：

```shell
copy secret.template.json secret.json
# 或
cp secret.template.json secret.json
```

生产必须完成：
- 使用环境变量提供密钥（`SESSION_SECRET`、`APP1_JWT_KEY`、`APP2_JWT_KEY` 等）
- 每个 app 都配置独立 JWT 密钥（`<APPID>_JWT_KEY`）
- callback 地址写入 `applist.json` 的 `callback_whitelist`
- 核对 `APP_URL` 与真实对外访问地址（含子路径）一致

## 3. 关键配置说明

### 3.1 .env 核心项

- `NODE_ENV`: 建议 `production`
- `APP_URL`: 服务对外地址，可带子路径，例如 `https://mc.jxufe.edu.cn/authbridge`
- `CAS_BASE_URL`: CAS 服务基址
- `CAS_VALIDATE_PATH`: 默认 `/cas/serviceValidate`
- `CAS_TIMEOUT_MS`: CAS 校验超时，默认 `10000`
- `SESSION_USE_REDIS`: 生产建议 `true`
- `SESSION_STORE`: `redis` 或 `memory`
- `REDIS_URL`: Redis 连接地址
- `TRUST_PROXY_HOPS`: 反向代理层级，常见为 `1`
- `ENABLE_DEBUG_API`: 生产建议 `false`

### 3.2 applist.json

示例（app2 使用 ECC）：

```json
{
	"apps": [
		{
			"appid": "app2",
			"app_aud": "app2-client",
			"jwt_expires_in": "15m",
			"encrypt_type": "ecc",
			"callback": "https://app2.example.com/api/auth/callback",
			"callback_whitelist": [
				"https://app2.example.com/api/auth/callback"
			]
		}
	]
}
```

说明：
- `callback` 为默认回调地址
- `callback_whitelist` 用于白名单校验，必须命中
- `jwt_expires_in` 为该应用 JWT 的独立有效期（支持 `15m`、`1h`、`7d` 或秒数）
- 未配置 `jwt_expires_in` 时，回退到 `.env` 的 `JWT_EXPIRES_IN`

### 3.3 secret.json

说明：默认策略为“环境变量优先”。
- `NODE_ENV=production` 时默认不回退 `secret.json`
- 非生产环境默认允许回退 `secret.json`
- 可通过 `SECRET_FILE_FALLBACK=true/false` 强制控制

示例：

```json
{
	"sessionSecret": "replace-with-strong-session-secret",
	"appSecrets": {
		"app2": {
			"jwt_key": "replace-with-app2-jwt-signing-secret",
			"ecc_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
			"ecc_private_key": ""
		}
	}
}
```

ECC 注意：
- 可以使用真实换行 PEM，必须用 `\n` 转义换行
- 如果把 PEM 内容写坏，会导致 `ERR_OSSL_UNSUPPORTED` 等解析错误
- `ecc_public_key` 用于上行加密；本服务端不要求必须配置 `ecc_private_key`

推荐环境变量（以 app1/app2 为例）：
- `SESSION_SECRET`
- `APP1_JWT_KEY`
- `APP1_AES_KEY`
- `APP2_JWT_KEY`
- `APP2_ECC_PUBLIC_KEY_B64`
- `APP2_ECC_PRIVATE_KEY_B64`

## 4. 启动方式

生产：

```shell
npm run build:css
npm run start
```

开发（两个终端）：

```shell
# 终端 1
npm run watch:css

# 终端 2
npm run dev
```

## 5. 登录与回调流程

登录入口：

```http
GET /login?appid=app2&mode=callback&callback=https%3A%2F%2Fapp2.example.com%2Fapi%2Fauth%2Fcallback
```

参数说明：
- `appid` 或 `app`: 目标应用 ID（必填，除非配置了 `DEFAULT_APP_ID` 或仅有一个应用）
- `mode`: `callback` 或 `page`
- `return`: `mode` 的别名
- `callback`: 临时覆盖回调地址（必须在白名单中）
- `service` 或 `target`: 登录完成后跳转目标，优先级最高

返回模式：
- `mode=callback`: 生成目标应用 JWT 后回调
- `mode=page`: 跳转 `/jwt` 展示 token
- 未传 `mode`: 按应用配置自动选择（`return_mode` 优先；未配置时有回调白名单则 `callback`，否则 `page`）

推荐约定：
- 无法接收 HTTP 回调的应用（如机器人后端）设置 `return_mode=page`
- 需要服务端接收 token 的应用设置 `return_mode=callback` 并配置 `callback_whitelist`

当前实现要点：
- 登录前会把 `appid/mode/callback/state` 写入会话并显式 `session.save`
- CAS `service` URL 会携带回调上下文与 `state`
- CAS 回调必须命中完整会话上下文（`authState/targetApp/returnMode/casFixedServiceUrl`）
- CAS 回调 `state` 采用严格匹配（缺失或不一致都会拒绝）
- CAS 验票时如果首次超时，会自动重试一次
- 同 ticket 重放会被拒绝，要求重新发起登录

### 回调后端实现建议与示例

AuthBridge 在 `mode=callback` 场景下会通过浏览器自动 POST 一个表单到目标应用的回调地址，表单字段包含：

- `token`: 服务端为目标应用签发的 JWT（HS256 或按应用配置）
- `studentId`: 认证得到的用户标识（便于回调方做审计或二次确认）
- `timestamp`: 生成时间戳

回调方后端收到该 POST 请求后应当：

- 在服务器端验证 JWT 签名与有效期（不要信任前端传来的任何声明）
- 验证通过后，由回调方后端在自己的域下写入 HttpOnly 的会话 Cookie 或直接建立本地 session（AuthBridge 无法替其它域写 cookie）
- 对于跨主域场景，推荐后端在验签成功后**不再把 JWT 暴露给前端**，而是直接将登录态映射为本地会话（Set-Cookie 或 服务器端会话存储）
- 在无法避免前端接触 token 时，优选短期 token、一次性 code 交换或额外的防重放/绑定策略

安全要点：

- 回调请求与回调地址必须走 HTTPS，全链路加密
- 回调方后端应开启严格日志脱敏，避免记录请求体中的 `token`
- 回调方需验证 token 的签名、`exp`，并根据业务需要校验载荷（如 `enc`、`sub` 等）
- 若回调方需要跨域接收（不同主域），推荐采用“一次性 code -> 后端换取 token”的方式，避免浏览器长期持有敏感 JWT

示例模板：仓库中包含一个 `demo-backend` 目录，作为回调后端实现参考（被 `.dockerignore` 忽略）。AuthBridge 的中转页当前使用 shared layout 派生，并通过外部脚本自动提交表单，避免内联脚本触发 CSP 拦截。示例实现演示如何接收 POST、验签并在本域写入 HttpOnly cookie。请根据生产密钥替换示例中的 `DEMO_APP_JWT_KEY`。

示例目录： [demo-backend](demo-backend)

## 6. 白名单规则

- 仅允许 `http` / `https`
- 按 `origin + pathname` 匹配
- 白名单项不带 query 时，允许动态 query（如 `token`、`timestamp`）
- 白名单项带 query 时，要求 query 完全一致

## 7. 生产安全基线

- 不要使用模板密钥和弱密钥
- 生产环境保持 `ENABLE_DEBUG_API=false`
- `POST /api/verify-jwt` 默认关闭
- 反向代理场景务必设置 `TRUST_PROXY_HOPS`
- 使用 HTTPS 暴露服务
- Redis 对外网不可直连

## 8. 常见故障排查

### 8.1 callback 没触发，反而进入 /jwt

检查项：
- 登录 URL 是否带了正确 `appid`
- `mode=callback` 是否传入
- `callback` 是否命中对应 app 白名单
- `APP_URL` 是否与真实访问地址（含子路径）一致
- Redis 会话是否可用

### 8.2 回调页面停在 AuthBridge 的中转页

现象：`/cas/serviceValidate` 返回 200，但浏览器一直停留在 AuthBridge 的“正在跳转到应用...”页面，没有继续 POST 到回调方。

排查项：
- 浏览器是否拦截了页面脚本执行
- 回调地址是否返回了可访问的 HTTPS 页面
- 回调方是否对 `POST /api/auth/callback` 做了跨域或代理层限制
- 页面源码里是否能看到 `callbackUrl`、`token`、`studentId` 三个隐藏字段
- 打开浏览器开发者工具，看 Network 里是否真的发出了 POST 请求

### 8.3 CAS 校验超时

现象：日志出现 `timeout of 10000ms exceeded`

处理：
- 检查应用服务器到 CAS 的网络连通性
- 适当增大 `CAS_TIMEOUT_MS`
- 检查网关/WAF 是否拦截 CAS 校验请求

### 8.4 ECC 报错 ERR_OSSL_UNSUPPORTED

通常是公钥格式问题：
- PEM 头尾丢失
- 换行被写坏（`\\n` 与真实换行混乱）
- 不是 EC 公钥

建议直接使用 `npm run generate:ecc` 生成并替换。

## 9. 密钥生成命令

```shell
npm run generate:jwt
npm run generate:aes
npm run generate:ecc
npm run generate:rsa
```

说明：
- RSA 仅保留兼容工具链，不是默认链路
- 每个应用应使用独立密钥

## 10. 上线检查清单

- [ ] `.env`、`applist.json` 已按生产填写，密钥已通过环境变量注入
- [ ] `APP_URL` 与反代路径一致
- [ ] `callback_whitelist` 已覆盖所有合法回调
- [ ] `SESSION_USE_REDIS=true` 且 Redis 正常
- [ ] CSS 已执行 `npm run build:css`
- [ ] 通过一次完整 `mode=callback` 登录回调验证
- [ ] 检查日志无 `CAS票据校验失败`、`ERR_OSSL_UNSUPPORTED`

## 11. 许可证

MIT License © 2026 Mine-JUFE
