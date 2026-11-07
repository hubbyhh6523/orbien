# TencentDB Agent Memory：Ubuntu + Docker 本地安装与测试

本文用于 Ubuntu 本地部署 Memory Core、Memory Hub、Memory Proxy，并在服务可用后测试 Octop 的 OpenAI-compatible Chat Completions 接入。它不是生产部署安全基线，也不代表 Orbien 已集成 TDAI。

**执行状态：仅完成源码核查和操作示例的静态语法检查，尚未完成容器安装、启动、模型调用或 Octop 端到端测试。当前助手执行环境未检测到 Docker CLI。** 请在目标 Ubuntu 主机执行，并以实际检出的安装文档、脚本和运行镜像为准。

## 版本与测试边界

前序核查使用的源码快照：

- TDAI：`2002196f2d7c22ea267cfcaf67c5a6fa861df681`，见[固定提交部署目录](https://github.com/TencentCloud/TencentDB-Agent-Memory/tree/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images)。
- Octop：`4022e24ef6c34e9716350872b0e93bfaae7a20c3`，见[固定提交](https://github.com/TencentCloud/Octop/tree/4022e24ef6c34e9716350872b0e93bfaae7a20c3)。

这些是源码核查依据，不是已部署版本。默认 `latest` 镜像可变，Git 提交不能证明运行镜像包含同版本代码；现场另行记录镜像 ID/digest，参见[镜像及环境模板](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/.env.example)。

本次测试范围：

- 检查容器、面板及健康接口。
- 先直连 Proxy 测试 Chat Completions，再接 Octop。
- 分别验证身份绑定、原始对话写入、记忆抽取和后续召回/注入。
- 不假设 Octop 有原生 TDAI 适配器，也不假设其历史数据库已自动导入。
- 只使用虚构、非敏感内容；配置外部模型 API 时，对话仍可能发送至该服务，本地部署不等于本地推理。

## 主机准备

未安装 Docker 时，按 [Docker 官方 Ubuntu 安装说明](https://docs.docker.com/engine/install/ubuntu/)操作；不要在未知主机上直接卸载现有 Docker 或执行未经检查的一键重装。

目标主机应具备 Git、Bash、curl、Docker Engine；本文 Python 冒烟示例另需 Python 3。TDAI 当前 global-images 脚本直接调用 `docker run`，Compose 不是该启动路径的必要条件；如果 Octop 使用 Compose，则另外准备 Compose 插件，见[Proxy 启动源码](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-proxy.sh)。

启动前检查系统信息、`git --version`、`docker --version` 和 `docker info`；使用 Compose 时再检查 `docker compose version`。Docker daemon 不可用时，先排查宿主机服务与权限，不要通过开放 Docker socket 权限绕过问题。

准备两组模型配置：`MEMORY_LLM_*` 用于记忆处理，`PROXY_UPSTREAM_*` 用于转发对话，可按脚本提示复用。本次测试的 Proxy 上游应实际支持 Chat Completions；不要把只支持其他协议的接口当作同协议实测通过，见[环境模板](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/.env.example)。

## 获取与首次配置

```bash
git clone https://github.com/TencentCloud/TencentDB-Agent-Memory.git tencentdb-agent-memory
cd tencentdb-agent-memory
git branch --show-current
git rev-parse HEAD
cd deploy/global-images
less ../../INSTALL_CN.md
less README.md
less .env.example
umask 077
[ -f .env ] || cp .env.example .env
chmod 600 .env
${EDITOR:-nano} .env
```

不要覆盖已有 `.env`，不要把 Markdown 链接语法粘贴进 `git clone`。如果希望独立执行 `verify.sh`，先填完模板必填项；也可以在完成下节网络检查后直接走 `start-all.sh` 的交互配置流程。启动脚本会创建缺失的 `.env`、询问两组配置并检查连通性，见[启动源码](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-all.sh)。

该快照的 README 与脚本存在 gateway Key 默认值描述差异：Core 脚本保留空 `MEMORY_CORE_GATEWAY_API_KEY`，并提示 Proxy 请求鉴权接口时的 Bearer 兼容限制。不要仅依据 README 的旧默认值改成非空，应结合镜像实测处理，见[Core 启动源码](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-memory-core.sh)。这一限制不应被推广为生产配置，测试 Core 必须置于隔离网络中。

## 限制端口发布

原启动脚本使用未指定宿主机 IP 的 `-p`，不能仅凭“本地测试”就认为只绑定 localhost。Docker 默认可能将其发布到所有接口，参见[官方端口发布说明](https://docs.docker.com/engine/network/port-publishing/)。

首次全新部署可先创建默认回环绑定的 `tdai-memory-stack` bridge 网络。下面命令遇到已有但不符合要求的网络时退出，不自动删除或重建资源：

```bash
(
  set -eu
  network=tdai-memory-stack
  if docker network inspect "$network" >/dev/null 2>&1; then
    driver=$(docker network inspect "$network" --format '{{.Driver}}')
    bind=$(docker network inspect "$network" --format '{{index .Options "com.docker.network.bridge.host_binding_ipv4"}}')
    if [ "$driver" != bridge ] || [ "$bind" != 127.0.0.1 ]; then
      printf '%s\n' '现有网络不符合本地回环绑定要求；先人工检查，禁止继续启动。' >&2
      exit 1
    fi
  else
    docker network create --driver bridge --opt com.docker.network.bridge.host_binding_ipv4=127.0.0.1 "$network" >/dev/null
  fi
)
```

**仅该步骤成功后才继续。** 已有部署另行规划绑定变更，不为套用示例删除数据卷或网络。该选项的含义和 Docker 28.0.0 以前的 localhost 端口访问限制见[官方说明](https://docs.docker.com/engine/network/port-publishing/)；回环绑定不能替代主机隔离与实际验证。

## 启动与基础验收

以下 `verify.sh` 适用于 `.env` 必填项已填写的情况；否则先走交互启动，不要把首次缺配置当作部署故障。

```bash
./verify.sh
./start-all.sh
```

不要录屏或公开完整启动输出：脚本可能显示管理用户 Key，见[启动脚本](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-all.sh)。

该版本的 OpenAI 预检主要访问上游 `/models`，遇到 404 还可能转试 Anthropic 探测。因此预检不是完整 Chat Completions 测试；`verify.sh --skip-llm` 也不是 `start-all.sh` 的通用跳过参数，见[校验脚本](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/verify.sh)。

默认端口如下，改过 `.env` 时必须使用实际值，参见[模板](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/.env.example)及对应启动脚本。

| 服务 | 默认容器 | 默认宿主机地址 |
|---|---|---|
| Core | `tdai-memory-core` | `http://127.0.0.1:8420/health` |
| Hub 面板 | `tdai-memory-hub` | `http://127.0.0.1:8125/` |
| Hub Knowledge | 同上 | `http://127.0.0.1:8424/health` |
| Proxy | `tdai-proxy` | `http://127.0.0.1:8096/health` |

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
for c in tdai-memory-core tdai-memory-hub tdai-proxy; do
  docker inspect "$c" --format '{{.Name}} state={{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}not-defined{{end}}'
  docker inspect "$c" --format '{{.Name}} image={{.Config.Image}} image_id={{.Image}}'
done
curl --fail-with-body --silent --show-error http://127.0.0.1:8420/health
curl --fail-with-body --silent --show-error http://127.0.0.1:8424/health
curl --fail-with-body --silent --show-error http://127.0.0.1:8096/health
```

映射应符合计划中的 `127.0.0.1:...`，不要把 `0.0.0.0:...` 或 `[::]:...` 接受为“仅本机访问”。确认面板可登录，再创建/确认测试 Team、Agent、当前用户权限及用户 API Key；Task 可选，不能编造 ID，见[官方 Pi 接入说明](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryCore/pi-plugin/README.md)。

## 凭证与重启注意

除 `.env`，还要保护 `.admin-key`、`.proxy-config/`、`.memory-core-config/`。不要上传原始日志、公开终端截图或启用含密钥流程的 `set -x`。

```bash
git check-ignore -v .env .admin-key .proxy-config/config.yaml .memory-core-config/tdai-gateway.yaml
git ls-files -- .env .admin-key .proxy-config .memory-core-config
git status --short
```

`git ls-files` 不应列出这些本地秘密文件；Git ignore 不是加密存储。仓库当前 ignore 规则见[固定提交](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/.gitignore)。

`start-proxy.sh` 会重新生成 YAML，直接改生成文件不能可靠持久化。单独运行该脚本的默认能力与全栈启动不同；测试记忆时在本地配置明确设置 `PROXY_FULL_STACK=1`，并检查生成配置的 auth、session-init、TDAI 开关，见[Proxy 脚本](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-proxy.sh)和[全栈脚本](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-all.sh)。

## 先做直连冒烟

不要把 `octop` 或 `openai` 随意填成 agent-source。官方 Pi 接入包含 OpenAI Chat Completions、身份预选和会话头，可以将 `/pi/{spaceId}/v1` 作为单用户兼容实验候选，但这不代表 Octop 原生适配或已经验证成功，见[Pi 接入说明](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryCore/pi-plugin/README.md)。

仅当端口未修改、space 确为 `default` 且当前镜像包含该画像时，候选 base URL 才是 `http://127.0.0.1:8096/pi/default/v1`。先从目标网络环境确认地址，不要添加未核实的 `/proxy` 前缀。

以下 Python 3 示例从交互输入读取用户 Key，不将其写入命令历史或命令行参数。它发送虚构工程消息，且仅测试非流式请求；Octop 的 SSE 流式行为还须另测。

```bash
python3 - <<'PY'
import getpass
import json
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
base = input('已核实的 base_url（含 /v1）: ').strip().rstrip('/')
u = urlsplit(base)
if u.scheme not in ('http', 'https') or not u.netloc or u.username or u.password or u.query or u.fragment or not u.path.endswith('/v1'):
    raise SystemExit('base_url 格式不正确；不得含凭证、查询参数或 fragment。')
model = input('已核实的模型 ID: ').strip()
team = input('实际 Team ID: ').strip()
agent = input('实际 Agent ID: ').strip()
if not all((model, team, agent)):
    raise SystemExit('模型、Team 和 Agent 均不能为空。')
key = getpass.getpass('TDAI 用户 API Key（不回显）: ')
if not key:
    raise SystemExit('用户 API Key 不能为空。')
headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json', 'x-team-id': team, 'x-agent-id': agent, 'x-conversation-id': 'tdai-smoke-' + uuid.uuid4().hex}
payload = {'model': model, 'stream': False, 'messages': [{'role': 'user', 'content': '虚构工程测试：paper-manta 项目的诊断 UDP 端口规定为 43127；修改网络代码前必须运行 cargo test。请简短确认。'}]}
req = Request(base + '/chat/completions', data=json.dumps(payload, ensure_ascii=False).encode(), headers=headers, method='POST')
try:
    with urlopen(req, timeout=180) as resp:
        print('HTTP', resp.status)
        result = json.load(resp)
        message = result.get('choices', [{}])[0].get('message', {})
        print('assistant:', message.get('content'))
        print('tool_calls:', bool(message.get('tool_calls')))
except HTTPError as exc:
    print('HTTP', exc.code)
    print('响应体仅在本机检查；不要未经脱敏公开。')
except URLError as exc:
    print('网络错误:', type(exc.reason).__name__)
PY
```

选择身份相关的工具调用不能当作真实上游回答。Pi 画像也可能在身份预选失败时绕过记忆继续聊天，应结合初始化和写入日志检查，见[初始化实现](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryProxy/src/session/codebuddy/init.ts)。

## Octop 配置与网络

在 Octop 配置 OpenAI-compatible Provider，选择 Chat Completions，不要默认选择 Responses。使用直连成功的 base URL、可用模型和 TDAI 用户 Key；不要混用 gateway token、管理接口凭证与上游模型 Key，参见[Octop Provider API](https://github.com/TencentCloud/Octop/blob/4022e24ef6c34e9716350872b0e93bfaae7a20c3/src/octop/api/routers/providers.py)。

前序源码核查确认该快照的 Provider 可通过 `extra_json.headers` 配置请求头；这不意味着所有 UI 版本都有独立编辑框，也不意味着会动态填入 Octop 线程 ID。以下仅是 `extra_json` 字段内部的对象形态；如果管理 API 将字段定义为 JSON 字符串，需要按 schema 正确序列化，而不是直接作为完整创建请求：

```json
{
  "headers": {
    "x-team-id": "填写实际 Team ID",
    "x-agent-id": "填写实际 Agent ID",
    "x-conversation-id": "仅供一个隔离冒烟会话使用的唯一标识"
  }
}
```

**固定会话头只适合一个隔离测试 Provider/会话，不应让多用户、多 Agent 或多个线程共用。** 正式接入需要把 Octop 稳定线程标识映射为动态会话头；不能推导自定义 TDAI Provider 自动具备这一能力，参见[Octop 会话头相关实现](https://github.com/TencentCloud/Octop/blob/4022e24ef6c34e9716350872b0e93bfaae7a20c3/src/octop/infra/agents/providers/opencode_session.py)及[官方 Pi 插件](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryCore/pi-plugin/README.md)。

Octop 若在容器内，`localhost` 指向该容器。确认 Compose 拓扑后，可将 Octop 服务加入 external 网络 `tdai-memory-stack`，通过 Proxy 网络别名 `proxy:8096` 访问，见[Proxy 网络配置](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-proxy.sh)。宿主机采用回环绑定时，不要默认认为 `host.docker.internal:宿主机端口` 仍可达，也不要为解决连通性直接开放公网端口。

## 分层验收

| 层级 | 必须取得的证据 | 不足以证明成功 |
|---|---|---|
| 服务就绪 | 容器状态、健康检查、面板可登录 | 镜像拉取成功 |
| 聊天转发 | 实际 POST 路径、上游转发、模型回复 | `/health` 或 `/models` 成功 |
| Octop 协议 | 实际使用的非流式/SSE 请求成功 | 只运行上面的非流式示例 |
| 身份绑定 | 用户、team/agent、session 初始化匹配 | 客户端发送了几个头 |
| L0 写入 | 对应 session 原始对话及写入记录 | HTTP 200 或模型说“记住了” |
| L1 抽取 | 任务完成并产生对应记忆 | 只有原始对话 |
| 后续召回/注入 | 新请求的检索/注入证据关联已存记忆 | 同一聊天历史中回答正确 |

官方接入说明建议检查 `agentSource`、直接注册和 `write-l0`。Core API 也分别定义原始对话、抽取和查询能力，见[Pi 验收说明](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryCore/pi-plugin/README.md)及[Core API 文档](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryCore/v3-api-memorycore-doc.md)。

```bash
docker logs --since 10m tdai-proxy 2>&1 | grep -E 'agentSource|register directly|write-l0|bypass|preset|TDAI_L0'
docker logs --tail 100 tdai-memory-core
```

日志可能包含对话和身份信息，只在本机检查，公开前脱敏。上述 grep 只是定位线索，不是自动验收程序。

该快照 Core 生成配置使用工程记忆模式，并配置 `everyNConversations: 5` 和 `l1IdleTimeoutSeconds: 600` 等异步处理参数；这些值不是固定完成时限，也不能解释成“必须发五轮”，见[配置生成源码](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/start-memory-core.sh)。普通闲聊可能不产生符合抽取规则的长期记忆。

先确认 L0，再等待或按当前面板功能触发抽取并检查结果。确认抽取完成后，用新的隔离会话询问 paper-manta 的诊断端口和修改前检查，不把旧事实重新放入请求，同时保持同一合法用户及 team/agent 范围。

若 Octop 自身也携带记忆或摘要，需使用干净测试 Agent，或单独直连 Proxy 复验；否则可能把 Octop 本地上下文误认成 TDAI 注入。不能据此宣称 Octop 历史数据库已经同步。

## 模型发现与排障

不要根据历史 issue 将 `/models` 缺失推广到所有版本。核查快照源码已经注册带 agent/space 的 models 路由，列表来自本地价格目录或模型池，不一定是实时上游完整模型列表，见[路由源码](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryProxy/src/server.ts)及[列表实现](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/MemoryProxy/src/modelsHandler.ts)。运行镜像是否包含仍需现场验证。

| 症状 | 优先检查 |
|---|---|
| `docker: command not found` | 是否在目标 Ubuntu 执行，Engine 是否安装 |
| 首次校验缺 `.env` | 先填配置，或走交互启动 |
| 健康成功但聊天失败 | 实际路由、模型、用户鉴权、容器到上游网络 |
| 模型列表失败或为空 | 镜像版本、请求前缀、模型目录；另测聊天 POST |
| 有回复但无记忆 | 全栈开关、权限、preset mismatch/bypass、L0 写入 |
| L0 有数据但无 L1 | 抽取模式、异步触发、Memory 组模型、任务日志 |
| 重启后记忆失效 | 是否单独启动 Proxy 导致能力开关变化 |
| Octop 拒绝内网 HTTP URL | 检查当前安全策略，不关闭 SSRF/出站保护掩盖问题 |

区分客户端到 Proxy 的用户鉴权与 Proxy 到模型上游的 API 凭证。对同一时间段的脱敏请求路径、状态和日志进行比对；不要因为宿主机探测成功就忽略容器内网络，也不要通过删除数据卷来“修复”未知错误。

## 停止与测试记录

当前停止脚本默认停止并移除容器、保留数据卷；`--purge` 涉及删除卷、网络及本地配置/凭证，不是普通停止选项，见[停止脚本](https://github.com/TencentCloud/TencentDB-Agent-Memory/blob/2002196f2d7c22ea267cfcaf67c5a6fa861df681/deploy/global-images/stop-all.sh)。

```bash
./stop-all.sh
```

不要使用 `--purge`、`docker compose down -v` 或删除 named volumes，除非已明确决定永久清理并确认备份和影响范围。

| 项目 | 当前结果 |
|---|---|
| 文档示例静态校验 | 本轮 8 个选定 Bash 示例通过 `bash -n`；Python 通过 AST 解析 |
| 目标 Ubuntu/Docker/Compose 版本 | 尚未取得，需现场记录 |
| 实际部署的仓库 SHA、镜像 ID/digest | 尚未取得 |
| 网络创建与端口绑定实测 | 未执行 |
| `verify.sh` 实际预检 | 未执行 |
| 容器启动、健康检查、面板登录 | 未执行 |
| Proxy 直连 Chat Completions | 未执行 |
| Octop 非流式/SSE 调用 | 未执行 |
| 身份绑定、L0、L1、后续注入 | 均未执行 |

现场另行记录请求时间、路径、状态、脱敏日志位置和分层验收证据，不记录密钥。本轮静态检查范围见 [tdai-static-check.txt](tdai-static-check.txt)。
