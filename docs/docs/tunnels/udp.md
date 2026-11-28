---
sidebar_position: 2
sidebar_label: UDP
title: UDP
---

# UDP

将内网 UDP 服务映射到服务端公网端口。

## 示例：穿透 DNS

服务端：

```toml
# orbien-server.toml
listen = "0.0.0.0:9527"
```

客户端：

```toml
# orbien.toml
server = "YOUR_SERVER_IP:9527"

[[tunnels]]
name = "dns"
protocol = "udp"
service = "127.0.0.1:53"
remotePort = 9000
```

外网访问：

```shell
dig @YOUR_SERVER_IP -p 9000 example.com
```

## 参数

| 参数                               | 必填 | 默认值         | 说明                          |
|----------------------------------|----|-------------|-----------------------------|
| `udpPacketSize`                  | 否  | `1500`      | UDP 最大报文长度，客户端与服务端需一致          |
| `udpMaxSessions`                 | 否  | `1024`      | 客户端每个 UDP 隧道最多同时服务的访客数（套接字/任务上限） |
| `name`                           | 是  |             | 隧道名称，唯一                     |
| `protocol`                       | 是  |             | 固定为 `udp`                   |
| `service`                        | 是  |             | 本地服务地址，如 `127.0.0.1:53`；支持 IPv6，如 `[::1]:53`    |
| `remotePort`                     | 是  |             | 服务端对外监听端口                   |
| `transport.bandwidth`            | 否  | `0`         | 带宽上限（Mbps）；`0` 表示不限制       |
| `transport.bandwidthLimitSide`   | 否  | `client`    | 限速端：`client` / `server`     |
| `transport.proxyProtocolVersion` | 否  |             | PROXY Protocol：`v1` / `v2`  |

## 安全限制（#14）

服务端只把回复发给最近 30 秒内向隧道发过报文的访客地址；客户端发来的、目标地址从未联系过隧道的回复会被丢弃并计数，服务端不会被当作反射器或扫描器。访客会话始终被跟踪，默认每条隧道最多 1024 个访客（服务端 `[limits]` 的 `maxUdpVisitorsPerTunnel`，客户端的 `maxConnections` 只能调低、不能调高）；超过上限、超过速率限制（默认每源 1000 包/秒、每隧道 10000 包/秒，可设为 `0` 关闭）或超过 `udpPacketSize` 的报文都会被丢弃，并在 `limit_rejections` 指标中按原因计数（`udp_no_visitor`、`udp_session_cap`、`udp_rate_limited`、`udp_truncated` 等）。单次 `send_to` 失败只丢弃该报文，不会中断整条隧道的回复。

**行为变更**：依赖“向从未联系过隧道的地址发包”的用法将不再工作；超过 `udpPacketSize` 的报文现在会被丢弃（之前是静默截断后转发）；被丢弃报文的字节不再计入流量统计。
