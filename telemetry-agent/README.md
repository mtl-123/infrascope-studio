# InfraScope Rust 采集客户端 0.1.0

这是一版可编译、可上报真实指标的客户端，不是完整监控需求的最终验收版。
复用现有 Go HTTPS 服务、平台身份、资产 ID、责任关系、权限和 PostgreSQL；不把数据库账号交给客户端。

## 二进制与职责

| 程序 | 数据来源 | 使用位置 |
| --- | --- | --- |
| `infrascope-agent` / `.exe` | 本机 CPU、内存、磁盘容量、网卡累计字节及连续采样速率、启动时间 | 每台 Windows / Linux 主机或虚拟机内部 |
| `infrascope-docker-collector` / `.exe` | Docker Engine 只读 API、容器状态、CPU 差分、内存与工作集、网络累计计数、Compose 名称分组 | 能访问 Docker Engine 的机器 |
| `infrascope-pve-collector` / `.exe` | PVE 节点、QEMU、LXC 状态与平台指标 | 能通过 HTTPS 访问 PVE API 的机器 |

PVE 平台指标不等于虚拟机内部 OS 指标。需要内部磁盘、网卡等信息时，在该虚拟机内另装主机 Agent，绑定其自己的资产。
三个客户端必须使用不同 `state_dir` 和各自类型的注册令牌。不要复制状态目录给其他机器。

### 平台范围

- Windows 包：x86-64，真实运行验证环境为当前 Windows 工作站。只依赖 Windows 系统 DLL；无需安装 Rust、Node、Python 或 MinGW。尚未做 Authenticode 签名。
- Linux 包：x86-64 GNU，要求 glibc >= 2.34 和 `libgcc_s.so.1`。已在当前 WSL Ubuntu 验证。不是 Alpine/musl、ARM64 或老版本 CentOS 通用包。
- Linux Docker 支持 Unix socket；Windows Docker 不支持 `npipe://`，需启用并限制访问的 HTTPS/mTLS Docker API。不要为方便而开放不加密的远程 Docker TCP。
- PVE 二进制和解析/错误测试已完成，但没有真实 PVE API 地址与 token，PVE 实机验收未完成。

## 从网页资产到真实上报

1. 登录原界面的“Agent 策略”，找到已登记、启用且填写责任人的资产。
2. 点击“注册客户端”，选 host / docker / pve，生成 10 分钟有效的令牌。每个令牌只能创建一个身份；同密钥在有效期内重试注册只恢复该身份。
3. 复制 `examples/host.toml` 等模板，填写服务端 HTTPS 地址和可信 CA 路径。跨机器不能用 `127.0.0.1`。不要将服务端数据库口令或 SSH/RDP 密码放入此配置。
4. 用下面的安全输入方式传递注册令牌，执行 `enroll`，随后执行 `once`。
5. 在“查看指标与 Agent”确认真实样本、入库时间和健康字段，再使用 `run` 持续运行。新鲜度不等于所有指标健康。

服务端当前本地开发地址为 `https://127.0.0.1:18443`，仅供这台电脑访问。其他机器部署前需给 Go 服务配置实际监听地址 `REMOTE_LISTEN`、可路由的 `REMOTE_PUBLIC_ORIGIN` 和匹配该 DNS 名称的 TLS 证书，并只开放必要的防火墙来源。客户端支持自定义 `ca_cert`，不支持关闭证书校验。

示例主机配置：

```toml
server_url = "https://monitor.example.com"
state_dir = "./host-state"
ca_cert = "./organization-ca.pem"
interval_seconds = 5
request_timeout_seconds = 15
max_queue_bytes = 67108864
max_queue_files = 10000
allow_insecure_loopback = false
```

相对路径基于 TOML 所在目录。使用公共受信 CA 时可省略 `ca_cert`。本机开发的自签名证书可复制 `.local-dev/tls/server.crt` 作为信任证书，**绝不可复制 `server.key`**。发布包不包含任何私钥、真实令牌或本机证书。

### Windows PowerShell

先把包放入当前用户拥有的私有目录，并检查状态目录 ACL，仅允许本用户及必要的管理员/SYSTEM 访问。主机采集不需要 UAC。

```powershell
Copy-Item .\examples\host.toml .\host.toml
# 编辑 host.toml 的 server_url、ca_cert 和独立 state_dir 后：
.\infrascope-agent.exe sample --config .\host.toml
$secret = Read-Host '网页注册令牌' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
  $env:INFRASCOPE_ENROLLMENT_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
  .\infrascope-agent.exe enroll --config .\host.toml
} finally {
  Remove-Item Env:\INFRASCOPE_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
.\infrascope-agent.exe once --config .\host.toml
.\infrascope-agent.exe run --config .\host.toml
```

退出用 Ctrl+C。私钥使用当前 Windows 用户 DPAPI 保护，之后必须使用同一账号；不能将交互用户的状态目录直接交给 LocalSystem 服务。
`run-service` 已实现 SCM 入口，随包提供前台启动脚本，但未擅自安装服务或测试重启自启，不能宣称 Windows Service 验收完成。

### Linux Bash

```bash
chmod +x ./infrascope-agent ./infrascope-docker-collector ./infrascope-pve-collector
cp examples/host.toml host.toml
# 编辑配置后，输入时不会把令牌写入 shell 历史：
read -rsp '网页注册令牌: ' INFRASCOPE_ENROLLMENT_TOKEN; echo
export INFRASCOPE_ENROLLMENT_TOKEN
./infrascope-agent enroll --config ./host.toml
unset INFRASCOPE_ENROLLMENT_TOKEN
./infrascope-agent once --config ./host.toml
./infrascope-agent run --config ./host.toml
```

Linux 状态目录 0700、状态和队列文件 0600。可选 systemd 模板及显式 sudo 安装脚本位于 `deploy/`；安装脚本不会注册、启动或启用服务。需以最终服务用户注册，并实测启动、停止和重启后上报，详见 `deploy/DEPLOYMENT.md`。

### Docker / PVE

使用对应模板和二进制，命令相同。Docker 默认 `unix:///var/run/docker.sock`。程序仅发出读取请求，但 Docker socket 本身是高权限资源；生产建议最小权限只读代理，不把“只读代码”等同于 socket 自带只读授权。

PVE 使用最小权限 API token，环境变量默认 `INFRASCOPE_PVE_TOKEN`，完整值格式为 `PVEAPIToken=user@realm!tokenid=secret`。通过安全输入或服务密钥注入，不写进 TOML、命令行或聊天。配置 `pve.ca_file` 信任 PVE CA。详见 `docs/COLLECTORS.md`。

## 服务端配置下发和可靠性

- 网页下发的配置只有版本、周期 1–3600 秒、启停和不可跨类型的采集器列表；不含任意脚本、命令、URL 或秘密。
- 注册后以服务端配置为准；本地 `interval_seconds` 是未取得配置时的起始值，不会覆盖已经接受的服务端配置。
- 配置在采集循环开始时拉取，验证并持久化后使用；拒绝版本倒退和同版本变更。网页分别显示期望版本、已应用版本，回执可能晚一个拉取周期。
- HTTPS 验证服务端，Ed25519 每设备签名验证客户端；时间窗、nonce 防重放。当前不是客户端证书 mTLS 方案。
- 样本先持久化到有界本地队列，服务端事务提交后才发 ACK。只有匹配 batchId 的成功 ACK 才删除本地批次，重试使用新 nonce。
- 队列默认 64 MiB / 10000 文件，满时拒绝新样本并记录丢弃，不静默覆盖老样本。丢弃计数目前是进程启动后计数，未实现跨重启累计指标。
- 断网时继续使用最后有效配置并缓存；撤销或认证失败不会伪造 ACK。`once` 失败返回非零；`run` 记录失败并继续重试。
- 计数用十进制字符串避免 JS 大整数精度损失。首个网卡样本无差分基线，速率为 null；连续 `run` 才产生后续速率。CPU 短窗口与网络实际间隔分别标注。

## 明确未完成的范围

真实 PVE 接入、Windows Docker HTTPS/mTLS、Windows SCM 与 Linux systemd 实机重启验收、生产规模性能与长时间稳定性仍未完成。尚无 ARM64/musl 包、自动签名更新、完整进程/磁盘 IO/登录审计采集。原导航中的其他演示监控页没有被本次自动变为真实数据。

服务端 30 天清理目前由该 Agent 的成功摄取触发；离线或撤销 Agent 不会自动全局清理。尚未实现完整时间分区、汇总和全局保留任务。不要将这些能力标为完成。

## 构建

```bash
source scripts/rust-env.sh
cargo test --manifest-path telemetry-agent/Cargo.toml --locked
cargo build --manifest-path telemetry-agent/Cargo.toml --release --locked
cargo build --manifest-path telemetry-agent/Cargo.toml --release --locked --target x86_64-pc-windows-gnu
```

发布包包含 SHA256 清单；校验和用于发现损坏，不等同于发布者数字签名。协议文档在 `docs/remote-access/TELEMETRY.md`，本轮测试证据见项目 `docs/implementation/TELEMETRY-2026-10-18.md`。
