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
copy secret.template.json secret.json
```

Linux/macOS：

```shell
cp .env.example .env
cp applist.template.json applist.json
cp secret.template.json secret.json
```

生产必须完成：
- 替换 `secret.json` 中全部示例密钥
- 每个 app 都配置独立的 `appSecrets.<appid>.jwt_key`
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
- `appid` 或 `app`: 目标应用 ID
- `mode`: `callback` 或 `page`
- `return`: `mode` 的别名
- `callback`: 临时覆盖回调地址（必须在白名单中）
- `service` 或 `target`: 登录完成后跳转目标，优先级最高

返回模式：
- `mode=callback`: 生成目标应用 JWT 后回调
- `mode=page`: 跳转 `/jwt` 展示 token
- 未传 `mode`: 有 `appid` 默认 callback，无 `appid` 默认 page

当前实现要点：
- 登录前会把 `appid/mode/callback` 写入会话并显式 `session.save`
- CAS `service` URL 会携带回调上下文，减少跨域跳转后的上下文丢失
- CAS 验票时如果首次超时，会自动重试一次
- 同 ticket 重放会尝试复用最近一次 callback 上下文

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

### 8.2 CAS 校验超时

现象：日志出现 `timeout of 10000ms exceeded`

处理：
- 检查应用服务器到 CAS 的网络连通性
- 适当增大 `CAS_TIMEOUT_MS`
- 检查网关/WAF 是否拦截 CAS 校验请求

### 8.3 ECC 报错 ERR_OSSL_UNSUPPORTED

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

- [ ] `.env`、`applist.json`、`secret.json` 已按生产填写
- [ ] `APP_URL` 与反代路径一致
- [ ] `callback_whitelist` 已覆盖所有合法回调
- [ ] `SESSION_USE_REDIS=true` 且 Redis 正常
- [ ] CSS 已执行 `npm run build:css`
- [ ] 通过一次完整 `mode=callback` 登录回调验证
- [ ] 检查日志无 `CAS票据校验失败`、`ERR_OSSL_UNSUPPORTED`

## 11. 许可证

MIT License © 2026 Mine-JUFE