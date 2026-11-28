---
sidebar_position: 2
sidebar_label: 管理界面
title: 管理界面
---

# 管理界面

服务端 Web 管理面板。 `port > 0` 时启用，启用后 **必须** 配置 `user` 与
`password`。

![dashboard.png](/img/dashboard.png)

## 示例

```toml
# orbien-server.toml
listen = "0.0.0.0:9527"

[dashboard]
addr = "0.0.0.0"
port = 8020
user = "admin"
password = "123456"
```

浏览器访问 `http://SERVER_IP:8020`，在弹出框输入用户名和密码登录。

:::tip
`addr` 默认为 `127.0.0.1`（仅本机），需远程访问时设为 `0.0.0.0`
:::

## 参数

| 参数                    | 必填 | 默认值         | 说明                   |
|-----------------------|----|-------------|----------------------|
| `webServer.addr`      | 否  | `127.0.0.1` | 监听地址；远程访问需 `0.0.0.0` |
| `webServer.port`      | 是  | `0`         | 监听端口；`0` 表示关闭        |
| `webServer.user`      | 是* |             | Basic Auth 用户名       |
| `webServer.password`  | 是* |             | Basic Auth 密码        |
| `webServer.assetsDir` | 否  |             | 静态资源目录；空则使用内置前端      |

\* 当 `port > 0` 时，`user` 和 `password` 为必填项，以防止未授权访问。

## 命令行

无配置文件时也可用参数开启：

```shell
./orbien-server --dashboard_port 8020 --dashboard_user admin --dashboard_pwd 123456
```

| 参数                 | 默认值       | 说明          |
|--------------------|-----------|-------------|
| `--dashboard_addr` | `0.0.0.0` | 监听地址        |
| `--dashboard_port` | `0`       | 监听端口；`0` 关闭 |
| `--dashboard_user` | (空)      | 用户名（必填）     |
| `--dashboard_pwd`  | (空)      | 密码（必填）      |

**安全提示**：当启用 dashboard（`--dashboard_port > 0`）时，必须显式提供 `--dashboard_user` 和 `--dashboard_pwd`，否则服务器将拒绝启动。请勿使用弱密码或默认凭据（如 admin/admin）。

## Token 策略

Monitor 页会展示每个 token 的活跃控制连接数，以及 `allowed_tunnels`、`allowed_protocols`、`allowed_remote_ports`。配置了策略但当前没有连接的 token 也会列出。

## API 响应约定

所有 `/api/v1/` 接口返回统一信封 `{ code, msg, data }`，列表为
`{ total, page, pageSize, items }`（`page` 从 1 开始，`pageSize` 钳制在
1~200，默认 50）。**HTTP 状态码与信封里的 `code` 一致**：出错时不再
返回 HTTP 200 嵌一个错误 `code`，而是直接返回对应的状态码（404、422
等），`msg` 里是错误原因。未知 `/api/*` 路径返回 JSON 404，永远不会
回落到前端 `index.html`。

## 踢出客户端

`DELETE /api/v1/clients/:id`（或 `POST /api/v1/clients/:id/kick`）断开
客户端的控制连接，`DELETE /api/v1/proxies/:name` 断开一条隧道：

- 被踢的客户端**直接退出，不会自动重连**，需要手动重新启动；正常断线
  （非踢出）才会按退避策略重连。
- 重复删除同一个客户端或隧道返回 404（`client not online` /
  `proxy not found`）。
- 踢出与客户端断线竞态时，若客户端已不在先，同样返回 404。

## 安全说明

- `disableAuth = true` 只允许在 loopback 地址上启动；配在非 loopback
  地址上服务器会拒绝启动。
- Dashboard 绑在非 loopback 地址、且没有 `https://` origin 时，启动会
  打出警告：Basic Auth 头与登录密码在明文 HTTP 上是裸奔的，请在前面放
  一个 TLS 反向代理。占位密码（如 `CHANGE_ME`）启动时直接拒绝。
- `GET /metrics` 与 `/api/` 走同一套鉴权（会话 Cookie、Basic Auth 或
  API key），不再公开；抓取时必须提供凭据。
- 登录、Basic Auth 与未知 API key 的失败共享同一个限流器：同一来源
  60 秒内失败 8 次后会被限流（429），窗口过去之前即使凭据正确也会被
  拒绝；IPv6 按 /64 前缀共享桶。
- API key 写操作还有每 key 限流：同一 key 60 秒内最多 60 次写请求，
  超过返回 429。
- 浏览器跨站请求会被拦截：`POST` / `PUT` / `DELETE` 带有与 `Host`
  不符的 `Origin`、或 `Sec-Fetch-Site: cross-site` 时返回 403；不带
  这些头的调用（如 curl）不受影响。
- 反向代理部署：`trustedProxies` 列出可信代理的 IP 或 CIDR，只有直连
  对端本身在列表里时才采信 `X-Forwarded-For` / `X-Forwarded-Proto`
  （用于限流键与 Cookie 的 `Secure` 标记）；不配时转发头一律忽略。
- WebAuthn 待处理态 120 秒过期、最多 64 个，`login/begin` 按地址限流；
  注册 passkey 只允许给当前登录用户（会话）或配置的 dashboard 用户
  （Basic Auth）注册。

## API Keys

给程序化调用准备的鉴权方式（#3，切片 2）：在配置文件里配
`[[dashboard.apiKeys]]`，调用时带 `Authorization: Bearer <key>`：

```toml
[dashboard]
port = 8020
user = "admin"
password = "CHANGE_ME"

# 每个 key：name 唯一，key 至少 32 个字符，scope 是 read（默认，只读）
# 或 read-write（可写）。
[[dashboard.apiKeys]]
name = "monitoring"
key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
scope = "read"
```

生成 key：

```shell
openssl rand -hex 32
```

```shell
curl -H "Authorization: Bearer <key>" http://127.0.0.1:8020/api/v1/system/info
curl -H "Authorization: Bearer <key>" http://127.0.0.1:8020/metrics
```

- `read` key 只能调用 `GET`（和 `HEAD`）接口，包括 `/metrics`；调
  `POST` / `PUT` / `DELETE`（reload、kick、删除）返回 403。
  `read-write` key 可以调用全部接口。
- 服务端运行时只存 key 的 SHA-256 哈希，不存明文；日志与响应里只出现
  哈希的前 16 位（key id），不会出现 key 本身。配置文件里是明文，
  请把配置文件设为 0600、不要提交到仓库。
- 改 key 只需改配置文件后调 `POST /api/v1/config/reload`（需要
  `read-write` key 或会话登录）：新增的 key 立即生效，被删的 key 立
  即失效；配置里有不合格的 key（太短、重名）时整个 reload 失败，
  旧 key 继续有效。
- 未知的 key 返回 401，并计入按地址的鉴权失败限流；每个 key 的写操作
  另有 60 次/分钟的限流，超过返回 429。
- API key 只走配置文件管理：没有新建/吊销接口，也没有对应的 UI 页面。

## Prometheus 监控

服务端内置 Prometheus 指标端点 `GET /metrics`，以标准文本格式暴露监控指标，可直接被 Prometheus / Grafana 抓取。**该端点需要鉴权**（会话 Cookie 或 Basic Auth），不再公开。

```shell
curl -u admin:123456 http://SERVER_IP:8020/metrics
```

返回示例：

```text
# HELP orbien_clients_online Current number of online clients.
# TYPE orbien_clients_online gauge
orbien_clients_online 3
# HELP orbien_traffic_in_bytes_total Total bytes received.
# TYPE orbien_traffic_in_bytes_total counter
orbien_traffic_in_bytes_total 12345678
# HELP orbien_proxy_connections_current Current connections per proxy.
# TYPE orbien_proxy_connections_current gauge
orbien_proxy_connections_current{proxy="web",type="http"} 5
```

### 指标列表

| 指标 | 类型 | 说明 |
|------|------|------|
| `orbien_clients_online` | gauge | 当前在线客户端数 |
| `orbien_clients_total` | gauge | 累计见过的客户端数 |
| `orbien_connections_current` | gauge | 当前活跃连接数 |
| `orbien_traffic_in_bytes_total` | counter | 累计接收字节数 |
| `orbien_traffic_out_bytes_total` | counter | 累计发送字节数 |
| `orbien_proxy_connections_current{proxy,type}` | gauge | 按代理的当前连接数 |
| `orbien_proxy_traffic_in_bytes_total{proxy}` | counter | 按代理的累计接收字节数 |
| `orbien_proxy_traffic_out_bytes_total{proxy}` | counter | 按代理的累计发送字节数 |

### Prometheus 抓取配置

```yaml
scrape_configs:
  - job_name: "orbien"
    static_configs:
      - targets: ["SERVER_IP:8020"]
    metrics_path: /metrics
```

> 注意：`/metrics` 与 dashboard 共用同一 Web 服务端口，且需要鉴权。抓取时需提供凭据（可通过 `basic_auth` 字段或反向代理注入）。

