---
sidebar_position: 1
sidebar_label: 身份认证
title: 身份认证
---

# 身份认证

客户端连接服务端时的 Token 鉴权。两端 `token` 必须一致，否则登录失败。Token 从配置文件读取，也可用环境变量注入，见 [环境变量](./env.md)。

:::tip
登录时用 token 计算 HMAC，不会把 token 明文发给服务端！
:::

## 示例

服务端：

```toml
# orbien-server.toml
[auth]
token = "YOUR_TOKEN"
```

客户端：

```toml
# orbien.toml
[auth]
token = "YOUR_TOKEN"
```

## Token 要求

- **长度**：至少 32 个随机字节。生成命令：`openssl rand -hex 32`。短于 32 个字符的 token 只会触发启动警告（`[short-token]`），不会被拒绝。
- **占位符**：服务端启动时会拒绝空 token、无 token 策略、占位 token（如 `YOUR_TOKEN`、`CHANGE_ME`）以及占位的 dashboard 密码。`--check-config` 只警告不断言，示例配置（含 `YOUR_TOKEN`）仍能通过检查。
- **服务端未配置 token 时**：启动即拒绝，不会以“不校验”方式运行。

## 登录流程（挑战-应答）

每次控制连接打开时，客户端先发一条空的 `Hello`（宣告新流），服务端回一条 `Challenge`（32 字节随机 nonce + 服务端版本），客户端再发 `Login`，其中 `challenge_response` 是以 token 为密钥的 HMAC-SHA256，消息为 `"login"` + 服务端 nonce + session id + 用户名 + 主机名 + pool 数量 + 版本 + capabilities。服务端校验 nonce 是本次连接签发的（一次性，用后即弃）且 HMAC 正确，否则拒绝并关闭连接。

`Hello` 必须先发：yamux 和 QUIC 都是懒打开多路复用流——对端只有在打开方第一次写数据时才知道这条流存在。客户端如果只读不写，服务端永远看不到这条流，双方会一直等下去；先发 `Hello` 就是宣告流的写操作。数据连接（`NewDataConn`）同理，也是先发 `Hello` 再读 `Challenge`。

这样设计的效果：

- **防重放**：截获的 Login 无法在另一条连接上重放——下一条连接的 nonce 不同；也没有时间窗口可钻。
- **防篡改**：session id、用户名、主机名、pool 数量、版本、capabilities 任一字段被改，应答即失效。
- **硬切断**：旧客户端不发 `Hello` 就直接发 Login，会被拒绝；没有过渡期。

`Login` 还带 `capabilities: ["challenge-auth-v1"]`，服务端会记录它；`version` 字段只做格式校验，不做版本比较——有没有合法的挑战应答就是新旧客户端的分界线。

### 服务端互相证明

`Login` 带客户端生成的 `client_nonce`，`LoginResp` 带 `server_proof`（HMAC-SHA256，消息为 `"login-resp"` + 客户端 nonce + 分配的 session id）。客户端收到 `LoginResp` 后立即验证，失败就断开，不会响应任何 `ReqDataConn`/`StartDataConn`。不知道 token 的假服务端无法让客户端打开本地连接。

注意：这是在已验证 TLS 之上的第二层保护，不是替代品——它防不住转发整段握手的中继者。

### 心跳与数据连接

- `Ping` 不再带任何字段：心跳证明不了任何东西（服务端以前就忽略它的摘要），控制流本身在登录时已经认证过。
- 数据连接（`NewDataConn`）的证明仍是 #11 的会话密钥 HMAC，但现在绑定到本条流的 Challenge nonce，而不是客户端自选的时间戳，因此没有重放窗口；旧的 `auth_digest`/`timestamp` 过渡字段已删除。

## 服务端证书验证（客户端默认验证）

控制连接默认走 TLS，且客户端**默认验证服务端身份**。以下三者至少要配其一，否则客户端拒绝连接：

| 配置 | 说明 |
|---|---|
| `transport.tls.trustedCaFile` | 信任的 CA 证书 |
| `transport.tls.tofuStoreFile` | TOFU 钉住存储文件（首次连接记录证书指纹，之后必须一致） |
| `transport.tls.insecureSkipVerify = true` | 显式放弃验证（旧默认行为；启动时警告存在中间人风险） |

```toml
# orbien.toml
[transport.tls]
# 三选一。只在自己控制的网络上用 insecureSkipVerify。
insecureSkipVerify = true
```

该规则对 TCP/TLS 和 QUIC 生效（同一套连接构造器），`--check-config` 不检查它（只警告 `[no-server-trust]`）。

### 钉住的是整张证书

TOFU 钉住的是整张服务端证书的 SHA-256（证书 DER 的哈希），不是 SPKI。换证书（即使同一把密钥）指纹也会变，需要重新钉住。

### 服务端自动生成的证书会持久化

服务端未配置 `certFile`/`keyFile` 时，会在配置文件旁边生成并保存一对自签名证书（`<配置名>.generated-cert.pem` / `<配置名>.generated-key.pem`，私钥 0600），重启时复用。以前每次启动都重新生成，指纹一变，钉住的客户端就连不上；现在指纹在删除这两个文件之前保持稳定。已有合法文件永不覆盖；文件损坏则启动失败（删掉两个文件可重新生成）。没有 `-c` 配置文件时（如测试、默认配置）仍是每次启动临时生成。

## 明文局域网

明文仍可作为显式选择使用：客户端 `transport.tls.enable = false`，服务端 `transport.tls.force = false`。只在可信局域网使用；不受信任的网络上明文不被支持。

## 参数

| 参数           | 必填 | 默认值 | 说明                     |
|--------------|----|-----|------------------------|
| `auth.token` | 是  |     | 共享密钥；至少 32 个随机字节；两端需一致 |

## Token 权限策略

登录通过后，还可按 token 限制能注册的 tunnel、协议和远程端口。策略里某一项为空时，该项不限制。

```toml
# orbien-server.toml
[auth]
token = "YOUR_TOKEN"

[[auth.token_policies]]
token = "team-a"
allowed_tunnels = ["db-prod", "metrics"]
allowed_protocols = ["tcp", "udp"]
allowed_remote_ports = [3306, 9125]
```

| 参数 | 必填 | 默认值 | 说明 |
|---|---|---|---|
| `auth.token_policies[].token` | 是 | | 要限制的客户端 token |
| `auth.token_policies[].allowed_tunnels` | 否 | `[]` | 允许注册的 proxy 名称；空表示不限制 |
| `auth.token_policies[].allowed_protocols` | 否 | `[]` | 允许的协议，如 `tcp` / `udp` / `http` / `https`；空表示不限制 |
| `auth.token_policies[].allowed_remote_ports` | 否 | `[]` | 允许的远程端口；空表示不限制 |

如果配置了任何策略，未列入策略的 token 将无法注册 tunnel（默认拒绝）；`allowed_domains` 为空时只允许 `rootDomain` 下的域名。策略会在 dashboard 的 Monitor 页展示。

## 命令行

服务端也可通过参数设置（会覆盖配置文件中的 `token`）：

```shell
./orbien-server -c orbien-server.toml -t YOUR_TOKEN
```

| 参数               | 默认值 | 说明   |
|------------------|-----|------|
| `-t` / `--token` |     | 共享密钥 |

## 已知限制

- **Windows 文件权限**：session id、resume secret、TOFU 存储、生成的服务端私钥在 Windows 上是普通写入，没有 ACL 保护；0600 权限只在 Unix 上生效。
- **互相证明不防中继**：见上文。

## 破坏性变更（#12 发布说明）

- **旧客户端被切断**：登录改为挑战-应答，旧客户端发出的 Login 会被拒绝；客户端与服务端必须一起升级。
- **客户端默认验证服务端**：没有 `trustedCaFile` / `tofuStoreFile` 且未设置 `insecureSkipVerify = true` 时，客户端拒绝连接（以前是静默跳过验证）。
- **服务端拒绝占位密钥启动**：空 token、无 token 策略、占位 token、占位 dashboard 密码都会导致启动失败；`--check-config` 不受影响。
- **钉住改为整张证书并持久化**：TOFU 钉住的是整张证书的哈希（以前文档误写为 SPKI）；服务端自动生成的证书现在保存到磁盘，重启复用，旧版每次启动换证书、钉住失效的问题不再出现。
