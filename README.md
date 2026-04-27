# Simple Secure Notes (BruceZ的简易Web云便签)

一个轻量的跨设备私密便签 Demo，目标是：

- 通过浏览器访问（HTTP）
- 服务端仅保存密文
- 多用户访问（每个用户独立 access-key）
- 访问需要密钥签名认证
- 支持多便签同步（新增、删除、编辑）

## 1. 运行方式

```bash
npm start
```

默认启动在 `http://127.0.0.1:8080`。

## 2. 用户初始化（SSH 后台）

首次使用请在服务器上添加用户：

```bash
node scripts/add-user.mjs -u alice
```

会输出该用户的 access-key（只显示一次），将它提供给用户登录网页即可。

可选：手动指定密钥

```bash
node scripts/add-user.mjs -u alice -k "your_custom_key"
```

也可以使用 npm 脚本别名：

```bash
npm run user:add -- -u alice
```

注意：不要执行 `npm add-user`（这是 npm 自带账号命令）。

删除用户（会同步删除该用户便签）：

```bash
node scripts/del-user.mjs -u alice
```

删除时会二次确认，必须输入 `DELETE` 才会执行。

也可以使用 npm 脚本别名：

```bash
npm run user:del -- -u alice
```

也可通过环境变量自定义路径：

`USERS_FILE_PATH=/path/to/users.json npm start`

用户库默认文件：

`config/users.json`

## 3. 安全模型

实现了以下保护：

- 客户端使用 `AES-GCM` 对便签明文加密后再上传
- 明文超过 2KB 时，客户端会先 `gzip` 压缩再加密，并在用户便签文件里记录 `plainCompression` 字段
- 服务端只存密文（按用户隔离，`data/notes/<userId>.json`）
- API 请求使用 `HMAC-SHA256` 签名认证
- 时间窗校验 + nonce 防重放（短时缓存）
- 用户的 access-key 保存在 `users.json` 中（由 SSH 后台脚本维护）
- 服务端使用 `HttpOnly` 会话 cookie（`ssn_session`）维持短期登录态

## 4. 使用说明

1. 输入 access-key 解锁后，界面会显示当前用户名。
2. 每个用户拥有独立便签空间，可新增、删除、编辑多条便签。
3. 每条便签都会显示创建时间和最近修改时间。
4. 浏览器会自动保持登录状态（刷新页面自动恢复，无需重复输入 key）。
5. 点击“锁定”会清除本地登录信息，并请求服务端注销会话。

## 5. 重要限制（必须阅读）

该项目运行在纯 HTTP 下，无法抵御强主动中间人（MITM）篡改页面/脚本。

这意味着：

- 中间人可替换前端脚本，窃取访问密钥
- 中间人可实时代理请求

因此此方案只适合低信任成本或内网自用场景。若要更强安全性，建议：

- 上 HTTPS（自签证书 + 证书固定，或反代 TLS）
- 或直接放到 WireGuard/Tailscale 等加密隧道内

## 6. 测试

```bash
npm test
```

当前测试覆盖签名认证核心逻辑（签名一致性与篡改检测）。
