---
sidebar_position: 5
sidebar_label: 获取真实 IP
title: 获取真实 IP
---

# 获取真实 IP

穿透后本地服务默认看到的是隧道地址。可用以下方式拿到访客真实 IP。

## PROXY Protocol

客户端连接本地服务时写入 PROXY Protocol 头。本地服务需支持解析（如 Nginx、HAProxy）。

```toml
# orbien.toml
server = "YOUR_SERVER_IP:9527"

[[tunnels]]
name = "web"
protocol = "tcp"
service = "127.0.0.1:80"
remotePort = 9000
transport.proxyProtocolVersion = "v2"
```

适用于 `tcp` / `udp` / `http` / `https`（透传）。`tls-term`（TLS终止） 不可用。

| 参数                               | 必填 | 默认值 | 说明                |
|----------------------------------|----|-----|-------------------|
| `transport.proxyProtocolVersion` | 否  |     | `v1` / `v2`；空表示关闭 |

## X-Forwarded-For

`http` 由服务端自动注入；`https` + `tls-term` 由客户端插件自动注入，无需额外配置：

- `X-Forwarded-For`：访客 IP
- `X-Forwarded-Proto`：`http` 或 `https`

应用从请求头读取即可。

## 说明

若 orbien-server 前还有 CDN / 负载均衡，需在服务端开启 PROXY Protocol，接收上游传递的真实 IP：

```toml
# orbien-server.toml
bindAddr = "0.0.0.0"
bindPort = 9527

proxyProtocol = true
proxyProtocolTrustedCidrs = ["10.0.0.0/8", "192.168.0.0/16"]
proxyProtocolTimeoutSecs = 5
denySrcCidrs = ["1.2.3.4/32"]
```

| 参数                          | 必填 | 默认值     | 说明                        |
|-----------------------------|----|---------|---------------------------|
| `proxyProtocol`             | 否  | `false` | 是否解析上游 PROXY Protocol     |
| `proxyProtocolTrustedCidrs` | 否  |         | 信任的上游 CIDR；空则不解析 PP 头 |
| `proxyProtocolTimeoutSecs`  | 否  | `5`     | 读取 PP 头超时（秒）              |
| `denySrcCidrs`              | 否  |         | 拒绝的访客源 CIDR               |

## 适用范围

- `denySrcCidrs`：对 TCP/UDP 隧道、控制端口（TCP/KCP/QUIC/WebSocket）和 HTTP/HTTPS 网关的访客都生效；被拒的访客在请求数据连接之前就被关闭。
- `proxyProtocol`：只在 TCP/HTTP/HTTPS 网关上解析上游 PP 头；控制端口和 UDP 不解析。不可信来源发来的 PP 头会被忽略。
- 访客 IP 以 PP 头里的为准（只认受信任上游发来的）；HTTP 网关按该访客 IP 注入 `X-Forwarded-For`。
