# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 并采用 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Security
- **denySrcCidrs 与 PROXY Protocol 现在真正生效**（#15）：两者之前只存在于配置与死代码中，从未对任何监听器生效。现在 `denySrcCidrs` 对 TCP/UDP 隧道、控制端口（TCP/KCP/QUIC/WebSocket）和 HTTP/HTTPS 网关的访客都生效，被拒连接在请求数据连接之前关闭；`proxyProtocol` 对 TCP/HTTP/HTTPS 网关生效，控制端口与 UDP 不解析 PP 头，不可信来源发来的 PP 头会被忽略。**行为变更**：已有 `denySrcCidrs` 配置的部署升级后会开始真正拦截；已开启 `proxyProtocol` 的部署，日志 / `X-Forwarded-For` / 客户端看到的访客 IP 将从上游地址变为 PP 头里的真实访客 IP。
- 移除未接入模块树的死代码 `server/src/proxy/`（http/mod/vhost）；其逻辑已由 `server/src/access/mod.rs` 的 `prepare_ingress` 统一实现。
- **UDP 隧道不再向任意地址发包，访客会话有上限**（#14）：服务端只把回复发给最近 30 秒内向隧道发过报文的访客地址，客户端指定的其他目标地址会被丢弃并计数；访客会话始终被跟踪，默认每条隧道最多 1024 个访客（`limits.maxUdpVisitorsPerTunnel`，客户端的 `maxConnections` 只能调低、不能调高）；新增每源 1000 包/秒、每隧道 10000 包/秒的速率限制（`limits.udpPacketsPerSecPerSource` / `limits.udpPacketsPerSecPerTunnel`，`0` 表示关闭）；超过 `udpPacketSize` 的报文会被丢弃并计数（之前是静默截断后转发）；单次 `send_to` 失败只丢弃该报文，不再中断整条隧道的回复；Windows 上收包时的 connection-reset 错误不再结束收包循环；客户端每个 UDP 隧道最多 1024 个访客套接字/任务（`udpMaxSessions`），本地服务支持 IPv6 地址。**行为变更**：依赖“向从未联系过隧道的地址发包”的用法将不再工作；被丢弃报文的字节不再计入流量统计；游戏等访客众多的服务如需更高上限请调高 `maxUdpVisitorsPerTunnel`。
- **SOCKS5 插件加固**（#17）：凭据改用常时比较；同一来源连续登录失败 5 次后锁定 10 分钟（`plugin.authMaxFailures` / `plugin.authLockoutSecs`，`0` 表示不锁定），登录失败按来源记日志（每分钟最多一条）；目标地址默认只放行公网地址，非公网地址（loopback / link-local / 私有地址段 / 未指定地址 / 组播 / 广播 / 文档 / 基准测试 / 保留 / CGNAT 地址段）及客户端自身的服务端地址一律拒绝，域名在客户端解析后按解析出的 IP 再检查一次，白名单 `plugin.allowedTargets`（CIDR 或单个 IP）优先于所有拒绝规则，`plugin.allowPrivateTargets = true` 可放行私有地址段（不放行服务端地址）；每条隧道最多同时转发 64 个连接（`maxConnections` 大于 0 时以它为准），转发连接空闲 300 秒后断开（`plugin.idleTimeoutSecs`，`0` 表示不限制）；短于 16 个字符的密码在启动时警告，未来版本将拒绝。**行为变更**：之前用该代理访问内网的配置，升级后会被拒绝，请按需加白名单或开 opt-in；凭据与代理流量仍是明文传输（SOCKS5 用户名/密码认证本身不加密，且 TLS 包装不是标准协议），请用长随机密码，不要把入口暴露给不可信网络。
- **Dashboard API v1 加固**（#3，切片 1）：`POST /api/v1/config/reload` 不再接受请求体里的 `configPath`，只重读启动时记录的配置文件，错误信息不再回显路径或文件行（TOML 解析错误只保留原因，读文件失败只保留固定前缀）；所有 JSON 错误的 HTTP 状态码现在与信封里的 `code` 一致（之前 kick/delete/reload 出错也返回 200，查不到的客户端/隧道返回无 body 的裸 404），未知 `/api/*` 路径返回 JSON 404 而不再回落到前端 `index.html`；`GET /metrics` 走与 `/api/` 同一套鉴权（会话 Cookie 或 Basic Auth），不再公开；`POST` / `PUT` / `DELETE` 遇到与 `Host` 不符的 `Origin` 或 `Sec-Fetch-Site: cross-site` 时返回 403（不带这些头的 curl/API 调用不受影响）；Basic Auth 失败计入与登录相同的限流器（60 秒 8 次，之后即使凭据正确也返回 429）；可信代理改为配置项 `dashboard.trustedProxies`（IP/CIDR 列表），只有直连对端本身在列表里时才采信 `X-Forwarded-For` / `X-Forwarded-Proto`，IPv6 限流键按 /64 前缀共享；WebAuthn 待处理态 120 秒过期、最多 64 个，`login/begin` 按地址限流；passkey 存储临时文件创建时即为 0600；passkey 注册只允许给当前登录用户或配置的 dashboard 用户；`disableAuth` 配在非 loopback 地址上拒绝启动；非 loopback 地址且无 `https://` origin 时启动警告；`system/health` 的 `uptimeSecs` 改为真实运行时间，`orbien_clients_online` 只计在线客户端。**行为变更**：依赖错误也返回 HTTP 200 的调用方需要按状态码处理；未鉴权的 `/metrics` 抓取会收到 401，请配凭据；`reloadConfig()` 不再发送 `configPath`；被踢的客户端直接退出不重连（见 dashboard 文档）。切片 2（API keys 与 scope）与切片 3（`DELETE /api/v1/tunnels/:name`、审计日志、OpenAPI 契约）不在本 PR 内。

## [0.2.0] - 2026-08-26

### Added
- 为 `orbien-core` 与 `orbien-client` 补充单元测试（配置解析、限流、消息编解码、代理协议、X-Forwarded-For、run_id、HTTPS2HTTP 请求改写），工作区测试总数从 28 增至 81。
- 新增 Prometheus 指标端点 `GET /metrics`，以标准文本格式暴露客户端数、连接数、总流量与按代理的流量/连接数。
- 安全：dashboard Web 服务新增安全响应头中间件（HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy）。
- 性能：为 `orbien-core` 新增 Criterion 基准测试 `cargo bench -p orbien-core`。
- 文档：dashboard 页新增 Prometheus 监控章节；新增《故障排查》指南。

### Security
- **路径穿越防护**（PR #7）：`load_pem_cert_key()` 现在拒绝 `certFile` / `keyFile` 路径中包含 `..` 的配置，防止通过精心构造的 TLS 配置路径读取任意文件。
- **Proxy 授权 fail-closed**（PR #14）：`authorize_proxy()` 在 `token_policies` 非空时，未列入策略的 token 将被拒绝，不再沿用旧的 fail-open 行为；新增测试覆盖此路径。
- **X-Forwarded-For / X-Forwarded-Proto 取最右值**（PR #18）：`client_key()` 和 `cookie_secure()` 改为取 header 链最右端可信值，防止攻击者通过在左侧注入伪造 IP 绕过限流或降级 Secure cookie。
- **日志注入防护**（PR #19）：新增 `client/src/sanitize.rs`，对来自服务端的不可信字符串（KickOut reason 等）在写入日志前清除 `
`/``、ANSI CSI 转义序列及其他控制字符，防止终端日志注入。
- **移除硬编码默认 dashboard 凭据**：服务端启动时强制校验 `dashboard.user` 和 `dashboard.password` 均非空（`dashboard.port > 0` 时），不再有内置默认值。
- **GitHub Actions SHA 固定**（PR #15/#26）：`ci.yml` 和 `release.yml` 中所有第三方 Action 引用替换为不可变 commit SHA，防止供应链攻击。
- **依赖升级**（PR #24）：`rand 0.8 → 0.10.2`，`tokio-tungstenite 0.26 → 0.30.0`，修复上游安全问题；同步适配 `rand 0.10` API（`RngExt` / `rand::rng`）。
- **Java 客户端依赖升级**：jackson-databind、jackson-core、spring-core、netty-handler、tomcat 系列（14 个 CVE）均通过 Aikido 修复至安全版本。

### Changed
- CI `RUST_VERSION` 从 1.88 升至 1.92，与 Slint 1.17.1 MSRV 及 `release.yml` 对齐。
- Cargo 缓存 key 升至 `v2`，强制刷新旧工具链缓存。
- CI Linux job 补充 Slint/winit 所需系统依赖（fontconfig、X11、Wayland dev 库）。

## [0.1.0] - 2026-08-24

首个统一版本。统一了 Cargo / Tauri / package.json / Java pom 的版本号为 `0.1.0`。

### Added
- 内网穿透核心：TCP / UDP / HTTP / HTTPS 代理
- 传输协议：TCP、KCP、WebSocket、QUIC，支持 TCP 多路复用（yamux）
- 安全：Token 隧道鉴权、TLS / mTLS 加密、HTTPS 透明转发与客户端 TLS 终止
- 限流：按代理配置带宽限制（KB / MB），支持 client / server 模式
- 连接限制：按代理配置最大并发连接数 `maxConnections`
- 控制心跳：服务端控制连接心跳与超时检测
- Token 级隧道访问策略：按 token 限制协议与远程端口
- WebAuthn 登录（passkey）+ 会话 Cookie 认证，与 Basic Auth 并存
- Web 管理界面：深色仪表盘、客户端 / 代理监控、踢出代理 API
- 跨平台桌面客户端（Tauri）与 Java 客户端（Spring Boot starter）
- HTTPS2HTTP 插件：在 agent 端终结 TLS 并转发到本地 HTTP

### Changed
- 鉴权摘要算法由 MD5 升级为 HMAC-SHA256（`privilege_key`）
- 消息读取增加超时，防止任务饥饿
- 提升 `JOIN_BUF` 至 512KB，调整 yamux 接收窗口

### Security
- 升级 yamux 0.13 → 0.14.0（GHSA-4w32-2493-32g7），固定 rustls 0.23.41
- 忽略 PROXY 协议，除非配置了受信 CIDR
- 拒绝过期的鉴权时间戳，收紧代理注册

### Fixed
- 修复 PROXY v1/v2 解析与构建的边界情况
- 修复 QUIC 客户端连接端口（应连 quicBindPort 而非 bindPort）
- 修复会话 / 代理替换时的资源泄漏
- 修复 dashboard 401 时重定向到登录页

## [0.0.4] - 2026-08-23

### Added
- 服务端 Web 管理界面初步版本
- 发布脚本与 musl 兼容包

## [0.0.3] - 2026-08-23

### Added
- Orbien v2 核心代码提交
- README 与文档

[Unreleased]: https://github.com/zzzhoo1/orbien/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/zzzhoo1/orbien/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/zzzhoo1/orbien/compare/v0.0.4...v0.1.0
[0.0.4]: https://github.com/zzzhoo1/orbien/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/zzzhoo1/orbien/releases/tag/v0.0.3
