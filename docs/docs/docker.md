---
sidebar_position: 4
sidebar_label: Docker 安装
title: Docker 安装
---

# Docker 安装

推荐在生产环境中使用 Docker 或 Docker Compose 方式部署 Orbien，便于管理生命周期与自动重启。

镜像托管于 GitHub Container Registry：
- 服务端：`ghcr.io/orbien-org/orbien-server:latest`
- 客户端：`ghcr.io/orbien-org/orbien:latest`

---

## 服务端

### 准备配置文件

创建 `orbien-server.toml`：

```toml
listen = "0.0.0.0:9527"

# 可选 通过域名路由
# httpGwPort = 80
# httpsGwPort = 443

# 可选：Token 鉴权
# [auth]
# token = "your-secret-token"

# 可选：Web 管理面板
[dashboard]
addr = "0.0.0.0"
port = 8020
user = "admin"
# 生成强口令：openssl rand -base64 24。切勿沿用示例值。
password = "CHANGE_ME_base64"
```

:::warning
`dashboard.addr` 需为 `0.0.0.0`，否则宿主机无法通过端口映射访问管理面板
:::

### 方式一：docker run

```shell
docker run -d \
  --name orbien-server \
  --restart unless-stopped \
  -p 9527:9527 \
  -p 8020:8020 \
  -v "$PWD/orbien-server.toml:/etc/orbien/orbien-server.toml:ro" \
  ghcr.io/orbien-org/orbien-server:latest
```

若同时需要 HTTP/HTTPS 虚拟主机，追加端口映射：

```shell
  -p 80:80 \
  -p 443:443 \
```

### 方式二：Docker Compose

```yaml
# docker-compose.yaml
services:
  orbien-server:
    image: ghcr.io/orbien-org/orbien-server:latest
    container_name: orbien-server
    restart: unless-stopped
    ports:
      - "9527:9527"
      - "8020:8020"
      # - "80:80"
      # - "443:443"
    volumes:
      - ./orbien-server.toml:/etc/orbien/orbien-server.toml:ro
```

```shell
docker compose up -d
```

<div id="env">

### 方式三：用环境变量注入配置

</div>

配置里写 <code>{'{{env.NAME}}'}</code>，用 `-e` 或 Compose `environment` 传入。语法见 [环境变量](./features/env.md)。

```toml
#orbien-server.toml
listen = "{{env.ORBIEN_LISTEN:0.0.0.0:9527}}"

[auth]
token = "{{env.ORBIEN_TOKEN}}"

[dashboard]
addr = "0.0.0.0"
port = 8020
user = "{{env.DASHBOARD_USER:admin}}"
# 无默认值：未设置 DASHBOARD_PASSWORD 时服务启动即报错，避免静默跑在弱口令上
password = "{{env.DASHBOARD_PASSWORD}}"
```

```yaml
# docker-compose.yaml
services:
  orbien-server:
    image: ghcr.io/orbien-org/orbien-server:latest
    container_name: orbien-server
    restart: unless-stopped
    ports:
      - "9527:9527"
      - "8020:8020"
    environment:
      ORBIEN_TOKEN: ${ORBIEN_TOKEN}
      DASHBOARD_PASSWORD: ${DASHBOARD_PASSWORD}
    volumes:
      - ./orbien-server.toml:/etc/orbien/orbien-server.toml:ro
```

```shell
export ORBIEN_TOKEN=YOUR_TOKEN
export DASHBOARD_PASSWORD=change-me
docker compose up -d
```

:::warning
字符串字段必须给占位符加引号；变量未设置且没有默认值时进程会启动失败。桌面客户端（Orbien-Desktop）不要在配置里写 <code>{'{{env.}}'}</code>。
:::

---

## 客户端

### 准备配置文件

创建 `orbien.toml`：

```toml
server = "YOUR_SERVER_IP:9527"

# 若服务端开启了 Token 鉴权，需保持一致
# [auth]
# token = "your-secret-token"

[[tunnels]]
name = "mysql"
protocol = "tcp"
service = "127.0.0.1:3306"
remotePort = 9000
```

:::tip 容器内 127.0.0.1 的含义
容器内的 `127.0.0.1` 指向容器自身，**不是宿主机**。  
若要穿透宿主机上的服务，请将 `localIP` 改为宿主机 IP，或改用 **host 网络模式**（见下文）。
:::

### 方式一：docker run（桥接网络）

```shell
docker run -d \
  --name orbien \
  --restart unless-stopped \
  -v "$PWD/orbien.toml:/etc/orbien/orbien.toml:ro" \
  ghcr.io/orbien-org/orbien:latest
```

### 方式一变体：host 网络模式
:::tip
容器内 `127.0.0.1` 是容器自己。若要穿透**宿主机**上的服务，把 `service` 改成宿主机 IP，或使用下方 host 网络
:::

使用 `--network host` 后，容器与宿主机共享网络栈，配置文件中可直接填写 `127.0.0.1` 访问宿主机本地服务：

```shell
docker run -d \
  --name orbien \
  --restart unless-stopped \
  --network host \
  -v "$PWD/orbien.toml:/etc/orbien/orbien.toml:ro" \
  ghcr.io/orbien-org/orbien:latest
```

> ⚠️ host 网络模式仅在 Linux 上有效；macOS / Windows 的 Docker Desktop 不支持此模式。

### 方式二：Docker Compose

```yaml
# docker-compose.yaml
services:
  orbien:
    image: ghcr.io/orbien-org/orbien:latest
    container_name: orbien
    restart: unless-stopped
    # 若需 host 网络，取消下行注释并删除 ports 配置
    # network_mode: host
    volumes:
      - ./orbien.toml:/etc/orbien/orbien.toml:ro
```

```shell
docker compose up -d
```

---

## 查看日志

```shell
# 实时查看服务端日志
docker logs -f orbien-server

# 实时查看客户端日志
docker logs -f orbien
```

## 监听器故障不再导致进程退出

服务端遇到 accept 失败（如文件描述符耗尽 EMFILE）时不再直接退出进程，
而是按 10ms 起步、指数退避（上限 1s）重试，同一监听器每 10 秒最多记录
一次；监听器自身异常退出会被记为错误。`restart: unless-stopped` 仍建议
保留，用于真正的致命错误；但不要再假定"监听器出问题进程就会退出重启"。
未登录连接的超时与数量上限见服务端配置 `[limits]`（默认登录超时 10 秒、
每 IP 最多 32 个未登录连接），详见严格配置检查文档。

## 升级镜像

```shell
docker compose pull && docker compose up -d
```

或使用 `docker run` 方式时：

```shell
docker stop orbien-server && docker rm orbien-server
docker pull ghcr.io/orbien-org/orbien-server:latest
# 重新执行 docker run 命令
```
