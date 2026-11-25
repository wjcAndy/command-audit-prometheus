# command-audit-prometheus

一个面向 Linux 服务器的命令审计与 Prometheus 指标导出器。项目基于 `auditd` 的 `execve/execveat` 内核审计事件，记录哪个用户执行了什么命令、参数、工作目录、进程身份和执行结果，并将危险命令转换为可用于 Alertmanager 告警的 Prometheus 指标。

当前版本为 **v0.2.0**。主交付物是 Go 标准库实现的静态单文件可执行程序，使用方式接近 `node_exporter`：下载对应架构的二进制、启用一次性 `auditd` 规则、直接运行即可。仓库同时保留 Python 参考实现，用于审计解析、规则和测试对照。

> 状态说明：本项目是可用 MVP，已在代码层完成单元测试和 HTTP 集成测试，但尚未在真实 Linux `auditd` 生产主机上完成端到端部署验证。事件缓存为内存实现，生产使用应补充持久化队列、事件存储、TLS 和审计防篡改措施。

---

## 1. 架构

```text
Linux kernel execve / execveat
          |
       auditd
          |
  /var/log/audit/audit.log
          |
  command-audit Agent
   - 解析 SYSCALL / EXECVE / CWD / EOE
   - 关联 auid / uid / euid / PID / CWD
   - 参数脱敏
   - 危险命令规则
          |
          +--------------------+--------------------+
          |                                         |
  Prometheus 直接拉取                         HTTP 主动推送
  Agent :9101/metrics                              |
                                          command-audit Server
                                          - 聚合事件
                                          - 去重与心跳
                                          - :9100/metrics
                                                  |
                                        Prometheus / Alertmanager
```

两条指标通路二选一：

- **拉取模式**：Prometheus 直接抓取每个 Agent 的 `/metrics`；不设置 `--server.url`。
- **推送模式**：Agent 推送事件和心跳到 Server；Prometheus 只抓取 Server 的 `/metrics`。

同时抓取 Agent 和 Server 会造成重复统计，不建议这样做。

---

## 2. 核心能力

- 基于内核 `auditd`，不依赖 Bash History；能覆盖脚本、服务、非交互进程等 `execve` 调用。
- 区分原始登录用户 `auid`、实际用户 `uid` 和有效用户 `euid`，降低 `sudo` 后丢失操作人身份的风险。
- 采集命令、脱敏参数、可执行文件路径、工作目录、PID、PPID、TTY、Session、退出状态和成功/失败结果。
- 参数只进入事件 JSON，不进入 Prometheus label；避免高基数和凭据泄露。
- 危险命令规则覆盖 `rm`、`reboot`、`poweroff`、`halt`、`shutdown`、`systemctl`、`init/telinit`、`dd of=/dev/*`、`mkfs`、`wipefs`、`fdisk`、`parted` 以及递归根目录权限修改。
- 支持 Bearer Token、事件去重、空闲心跳、离线检测、批量推送和有界指标标签。
- 提供 Linux `amd64`、`arm64` 静态 ELF 二进制；Windows 可执行文件仅用于参数验证，不能采集 Linux auditd 事件。

---

## 3. 前置条件

### 3.1 Linux auditd

程序本身解压即可运行，但内核审计源必须由系统启用一次。安装 `auditd`，然后部署仓库中的规则文件：

```bash
sudo cp deploy/99-command-audit.rules /etc/audit/rules.d/
sudo augenrules --load
sudo auditctl -l | grep command_audit
```

规则内容：

```text
-a always,exit -F arch=b64 -S execve -S execveat -k command_audit
-a always,exit -F arch=b32 -S execve -S execveat -k command_audit
```

Agent 默认读取 `/var/log/audit/audit.log`，因此运行账户需要该文件的读取权限；systemd 示例使用 `root`。

### 3.2 覆盖边界

`execve` 审计记录已执行的外部程序，但不会记录 shell 内建命令，例如 `cd`、`export`、`history`。全量 execve 审计在高频进程服务器上可能产生明显开销，建议先在测试环境压测，并按实际环境增加审计排除规则。

---

## 4. 快速开始

### 4.1 选择二进制

| 文件 | 平台 | 大小 | SHA256 |
|---|---|---:|---|
| `dist/command-audit-linux-amd64` | Linux x86-64，静态 ELF | 7,549,088 B | `78bd06a7d9acb0714fee3b9d269d19bcc13789843091bb0b3cb8f7240472347a` |
| `dist/command-audit-linux-arm64` | Linux AArch64，静态 ELF | 7,012,512 B | `fe1b1f2c1fb2afb78335d91722f5da9ed510d6fcdd0eea717a32fd6ee75f8956` |
| `dist/command-audit-windows-amd64.exe` | Windows x86-64，仅本地验证 | 7,802,368 B | `838c669a55a826e17bf0f68e34fdee0fe1ba10a1952cefdf5a4349442ad0da97` |

校验和另见 `SHA256SUMS.txt`。

```bash
chmod +x command-audit-linux-amd64
./command-audit-linux-amd64 --version
```

### 4.2 启动 Agent：Prometheus 直接拉取

```bash
sudo ./command-audit-linux-amd64 \
  --web.listen-address=0.0.0.0:9101 \
  --audit.log-path=/var/log/audit/audit.log
```

验证：

```bash
curl http://127.0.0.1:9101/healthz
curl http://127.0.0.1:9101/metrics
```

### 4.3 启动汇聚 Server：Agent 主动推送

Server：

```bash
export COMMAND_AUDIT_TOKEN='replace-with-a-long-random-token'

./command-audit-linux-amd64 server \
  --web.listen-address=0.0.0.0:9100 \
  --dangerous.commands=collect
```

Agent：

```bash
export COMMAND_AUDIT_TOKEN='replace-with-a-long-random-token'
export COMMAND_AUDIT_SERVER='http://server.example:9100'

sudo -E ./command-audit-linux-amd64 \
  --web.listen-address=0.0.0.0:9101 \
  --server.url="$COMMAND_AUDIT_SERVER"
```

Agent 每次最多推送 100 个事件，空闲时每 30 秒发送一次心跳。Server 对重试事件按 `dedupe_key` 去重，并通过心跳判断 Agent 是否在线。

### 4.4 不采集危险命令

三种策略：

| `--dangerous.commands` | 行为 |
|---|---|
| `collect` | 采集全部事件，并产生危险命令指标，默认值 |
| `no-alert` | 保留普通审计事件，但清空危险标记，不产生告警指标 |
| `drop` | 命中危险规则后完全丢弃，不进入事件 API、推送或常规命令指标 |

示例：

```bash
# 只关闭危险命令告警，仍保留事件
./command-audit-linux-amd64 --dangerous.commands=no-alert

# 完全不采集危险命令，同时不保存参数
./command-audit-linux-amd64 \
  --dangerous.commands=drop \
  --collector.args=false
```

`drop` 模式只产生不含用户、命令和参数的过滤计数：

```text
command_audit_events_suppressed_total{
  hostname="node-a",
  reason="dangerous_command"
} 1
```

Server 也支持同样的中央策略：

```bash
./command-audit-linux-amd64 server --dangerous.commands=drop
```

---

## 5. 命令行参数

统一入口默认运行 Agent，`server` 子命令运行汇聚端：

```bash
command-audit [agent] <flags>
command-audit server <flags>
```

### 5.1 Agent 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--web.listen-address` | `:9101` | 监听地址，例如 `:9101`、`127.0.0.1:9101` |
| `--audit.log-path` | `/var/log/audit/audit.log` | audit 日志路径；`-` 表示从 stdin 读取 |
| `--audit.from-start` | `false` | 是否读取已有日志；默认只读取启动后的新增记录 |
| `--audit.max-pending` | `10000` | 内存中未组装完成的审计事件上限 |
| `--hostname` | 系统主机名 | 指标中的 `hostname` 标签 |
| `--server.url` | 空 | 汇聚 Server 地址；空表示拉取模式 |
| `--auth.token` | 环境变量 `COMMAND_AUDIT_TOKEN` | Bearer Token；优先使用环境变量，避免出现在进程列表 |
| `--dangerous.commands` | `collect` | `collect`、`no-alert` 或 `drop` |
| `--collector.args` | `true` | 是否采集脱敏参数；支持 `=true`、`=false` |
| `--no-collector.args` | 未指定 | 等价 `--collector.args=false` |
| `--collector.max-recent` | `200` | 本地事件 API 保留数量；`0` 禁用事件缓存 |
| `--metrics.max-users` | `200` | `user` 标签基数上限，超出归入 `__other__` |
| `--metrics.max-commands` | `300` | `command` 标签基数上限，超出归入 `__other__` |
| `--push.batch-size` | `100` | 单次推送事件数 |
| `--push.queue-size` | `10000` | 内存推送队列大小 |
| `--push.timeout` | `5` | 推送 HTTP 超时，单位秒 |
| `--push.heartbeat-interval` | `30` | 空闲心跳间隔，单位秒 |
| `--log.level` | `INFO` | `DEBUG`、`INFO`、`WARNING`、`ERROR`、`CRITICAL` |
| `--version` | - | 输出版本 |

兼容旧参数：`--listen`、`--port`、`--input`、`--from-start`、`--max-recent`、`--server-url`、`--token`、`--dangerous-commands`、`--collect-args`、`--no-collect-args`、`--log-level`。

布尔参数支持以下写法：

```bash
--collector.args
--collector.args=true
--collector.args=false
--no-collector.args
--audit.from-start=true
```

### 5.2 Server 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--web.listen-address` | `:9100` | 监听地址 |
| `--server.max-events` | `10000` | 内存事件缓存大小；`0` 禁用 |
| `--dangerous.commands` | `collect` | 中央危险命令策略 |
| `--auth.token` | 环境变量 `COMMAND_AUDIT_TOKEN` | Bearer Token |
| `--log.level` | `INFO` | 日志级别 |
| `--version` | - | 输出版本 |

---

## 6. HTTP 接口

### 6.1 Agent

| 路径 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 健康检查，不要求认证 |
| `/metrics` | GET | Prometheus 文本格式 |
| `/api/v1/events` | GET | 最近事件；支持 `limit`、`dangerous=true` |

### 6.2 Server

| 路径 | 方法 | 说明 |
|---|---|---|
| `/healthz` | GET | 健康检查，不要求认证 |
| `/metrics` | GET | 聚合 Prometheus 指标 |
| `/api/v1/events` | GET | 查询事件；支持 `hostname`、`dangerous=true`、`limit` |
| `/api/v1/events` | POST | Agent 批量推送或心跳 |

设置 Token 后，除 `/healthz` 外的所有接口都需要：

```text
Authorization: Bearer <COMMAND_AUDIT_TOKEN>
```

查询危险事件示例：

```bash
curl -H "Authorization: Bearer $COMMAND_AUDIT_TOKEN" \
  'http://127.0.0.1:9100/api/v1/events?dangerous=true&limit=100'
```

事件 JSON 保留脱敏参数、用户身份、PID、CWD、执行结果和危险规则。密码、Token、API Key、私钥、环境变量密钥及 URL userinfo 会按规则替换为 `<redacted>`。该脱敏规则不是完整的 DLP 实现，不能替代敏感信息分类和日志访问控制。

---

## 7. Prometheus 指标

导出格式为 Prometheus text `0.0.4`。

| 指标 | 类型 | 说明 |
|---|---|---|
| `command_audit_events_total` | counter | 普通命令事件数，标签含 hostname、user、command、result |
| `command_audit_dangerous_events_total` | counter | 危险命令事件数，额外含 rule、severity |
| `command_audit_last_event_timestamp_seconds` | gauge | 最近事件时间戳 |
| `command_audit_agent_last_seen_timestamp_seconds` | gauge | Server 最近收到 Agent 事件或心跳的时间 |
| `command_audit_agent_up` | gauge | Agent 是否在线；本地抓取时恒为 1 |
| `command_audit_agent_events_dropped_total` | counter | 因缓冲区满而丢弃的事件 |
| `command_audit_parse_errors_total` | counter | 解析失败的审计记录数 |
| `command_audit_events_suppressed_total` | counter | 按策略主动过滤的事件数 |

示例：

```text
command_audit_dangerous_events_total{
  hostname="node-a",
  user="ops",
  command="rm",
  rule="root_recursive_delete",
  severity="critical"
} 1
```

重要约束：**命令参数不作为 Prometheus label**，否则会产生高基数并可能泄露凭据。完整参数只通过事件 API 查询，且已经过脱敏。

---

## 8. Prometheus 与 Alertmanager 配置

`deploy/prometheus.yml` 提供两种抓取方式。推送模式示例：

```yaml
scrape_configs:
  - job_name: command-audit-server
    static_configs:
      - targets: ["command-audit-server.example:9100"]
    # bearer_token_file: /etc/prometheus/command_audit_token
```

`deploy/alert_rules.yml` 包含：

- `CommandAuditDangerousCommand`：5 分钟内出现危险命令指标即告警，告警级别继承指标的 `severity`。
- `CommandAuditAgentDown`：`command_audit_agent_up == 0` 持续 2 分钟。
- `CommandAuditEventsDropped`：出现推送或解析丢弃事件。
- `CommandAuditParseErrors`：出现审计解析错误。

危险规则分级：

| 规则 | 严重度 | 典型命令 |
|---|---|---|
| `system_power_state` | critical | `reboot`、`poweroff`、`halt`、`shutdown`、`systemctl reboot` |
| `system_runlevel` | critical | `init 0/6`、`telinit 0/6` |
| `root_recursive_delete` | critical | `rm -rf /`、`--no-preserve-root` |
| `recursive_delete` | high | `rm -r build` |
| `file_delete` | warning | `rm file.txt` |
| `block_device_overwrite` | critical | `dd of=/dev/sda` |
| `disk_layout_modify` | critical | `mkfs`、`wipefs`、`fdisk`、`parted` |
| `root_permission_modify` | high | `chmod -R /`、`chown -R /` |

---

## 9. systemd 部署

将对应架构二进制复制为 `/usr/local/bin/command-audit`：

```bash
sudo install -m 0755 command-audit-linux-amd64 /usr/local/bin/command-audit
sudo mkdir -p /etc/command-audit
```

Agent 环境文件 `/etc/command-audit/agent.env`：

```ini
COMMAND_AUDIT_TOKEN=replace-with-a-long-random-token
COMMAND_AUDIT_SERVER=http://command-audit-server.example:9100
```

Server 环境文件 `/etc/command-audit/server.env`：

```ini
COMMAND_AUDIT_TOKEN=replace-with-a-long-random-token
```

安装单元：

```bash
sudo cp deploy/command-audit-agent.service /etc/systemd/system/
sudo cp deploy/command-audit-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now command-audit-agent
sudo systemctl enable --now command-audit-server
```

单元中已使用以下参数：

```text
Agent:  --web.listen-address=0.0.0.0:9101 --audit.log-path=/var/log/audit/audit.log --dangerous.commands=collect --collector.args
Server: server --web.listen-address=0.0.0.0:9100 --dangerous.commands=collect
```

---

## 10. 源码结构与构建

```text
.
├── main.go                 # Go CLI、Agent/Server 启动、日志读取
├── types.go                # 审计记录解析、用户解析、脱敏、危险命令规则
├── metrics.go              # 有界标签的 Prometheus 指标
├── app.go                  # Agent/Server 状态、HTTP 接口、推送器
├── main_test.go            # Go 单元与 HTTP 集成测试
├── build.py                # 跨平台静态二进制构建脚本
├── go.mod
├── Dockerfile              # 无运行时依赖的 Linux amd64 构建
├── Makefile
├── command_audit/          # Python 参考实现
├── tests/test_pipeline.py  # Python 测试
├── deploy/                 # auditd、systemd、Prometheus、Alertmanager 配置
└── dist/                   # 预编译可执行文件
```

构建当前平台：

```bash
python build.py --output dist
```

构建 Linux amd64 与 arm64：

```bash
python build.py --all-linux --output dist
```

Docker 构建 Linux amd64：

```bash
make docker-build
```

Go 源码使用标准库，`CGO_ENABLED=0`；Linux 二进制为静态 ELF。Python 参考实现依赖 Python 3.10+，安装后可使用：

```bash
pip install .
python -m command_audit --version
python -m command_audit server --version
```

---

## 11. 测试

```bash
make test
```

该命令会运行：

- Go 测试：审计解析、hex 参数、用户/PID、危险规则、脱敏、三种危险策略、指标输出、去重、心跳、HTTP 推送/查询、监听地址解析。
- Python 测试：对应解析、规则、HTTP、统一 CLI、显式布尔参数、危险策略。

当前验证结果：

- Go：9 项测试通过，`go vet` 通过。
- Python：15 项测试通过。
- Windows 可执行文件完成 `--version`、`server --version`、显式布尔参数和 stdin EOF 冒烟测试。
- ELF 头确认 Linux 两个二进制分别为 x86-64 / AArch64 静态链接。

---

## 12. 安全与生产化注意事项

1. 事件 JSON 可能包含业务敏感参数；即使经过脱敏，也应限制 `/api/v1/events`、日志文件、事件存储和网络访问范围。
2. `--auth.token` 会出现在进程列表；生产环境优先使用 `COMMAND_AUDIT_TOKEN` 环境变量或受控 EnvironmentFile。
3. 内置 HTTP 服务未提供 TLS；建议置于 Nginx、Envoy 或内网服务网格之后，并配置 mTLS/ACL。
4. 指标和事件均为内存状态，进程重启后清空。生产环境应增加磁盘发送队列、持久化事件存储、回放与容量监控。
5. 全量 execve 审计会带来 CPU、磁盘 I/O 和 auditd backlog 压力；应压测并调整 `auditd` backlog、日志轮转和排除规则。
6. 本地 root 可以停止 Agent 或修改 auditd 规则；高安全场景需将事件实时转发到独立日志系统，并启用审计规则锁定与远端防篡改。
7. 参数脱敏是通用规则集合，不是完整 DLP；上线前应按实际命令、凭据形态和合规要求复核。
8. `execve` 不能覆盖 shell 内建命令；如需完整交互会话审计，需要额外方案，例如受控 shell 审计或 TTY 审计，并单独评估隐私风险。
9. 如启用 Server 推送，应只抓取 Server 指标；如使用直接拉取，应只抓取 Agent 指标，避免重复计数。

---

## 13. 校验

```bash
sha256sum -c SHA256SUMS.txt
```

当前版本二进制校验值：

```text
78bd06a7d9acb0714fee3b9d269d19bcc13789843091bb0b3cb8f7240472347a  dist/command-audit-linux-amd64
fe1b1f2c1fb2afb78335d91722f5da9ed510d6fcdd0eea717a32fd6ee75f8956  dist/command-audit-linux-arm64
838c669a55a826e17bf0f68e34fdee0fe1ba10a1952cefdf5a4349442ad0da97  dist/command-audit-windows-amd64.exe
```
