### 安全初始化（必做）

首次部署请先复制模板文件并填充生产密钥：

``` shell
copy .env.example .env
copy applist.template.json applist.json
copy secret.template.json secret.json
```

注意：
- `.env.example` 默认 `NODE_ENV=production`。
- `jwtSecret` 与 `sessionSecret` 不能使用占位符，且建议至少 32 字符。
- `POST /api/verify-jwt` 已按安全策略关闭（返回 404）。
- `GET /api/debug/session` 在生产环境返回 404；非生产环境默认关闭，仅在 `ENABLE_DEBUG_API=true` 时可用。
- 上层回调地址需要在 `applist.json` 的 `callback_whitelist` 内声明。

### 密钥生成

jwt密钥请使用hex 16进制编码
或者可以使用generate_jwt.js生成，执行后会在控制台输出一个随机的256位（32字节）和128位（16字节）hex字符串，作为JWT的密钥使用。
``` shell
npm run generate:jwt
```
aes密钥请使用hex 16进制编码，长度可以选择16字节（128位）、24字节（192位）或32字节（256位）。例如，使用以下命令生成一个128位的hex密钥：
``` shell
npm run generate:aes
# 或者
node scripts/aes_generate.js 128 ./keys/aes_key
```
ecc密钥可用于 `encrypt_type=ecc` 的应用上行回调加密。可用以下命令生成 PEM 格式密钥对：
``` shell
npm run generate:ecc
# 或者
node scripts/ecc_generate.js prime256v1 ./keys/ecc_public.pem ./keys/ecc_private.pem
```
在 `secret.json` 中按应用配置：
```json
{
	"appSecrets": {
		"app1": {
			"ecc_public_key": "-----BEGIN PUBLIC KEY-----..."
		}
	}
}
```
如果你需要在其他内部服务里解出明文，可在对应服务配置 `ecc_private_key` 后自行调用解密逻辑。
虽然本项目不再使用rsa密钥，但如果需要生成，可以使用以下命令：
``` shell
npm run generate:rsa
# 或者
node scripts/rsa_generate.js 2048 ./keys/rsa_private_key ./keys/rsa_public_key
```
为保证安全，请为每个应用生成独立的密钥，并妥善保管，切勿泄露给第三方。
**并且请在生产环境重新生成所有密钥，切勿使用示例密钥。**
### 构建与运行

生产环境
``` shell
npm run build:css
npm run start
```
测试环境（请使用两个shell分别执行，以持续更新）
``` shell
# 终端1
npm run watch:css
# 终端2
npm run dev
```