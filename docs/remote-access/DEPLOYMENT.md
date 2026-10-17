# 集成与部署

## 宿主调查和复用

目标是既有 `infrascope-studio` 仓库，原发布基线 `ff470100c410030a6716e043fa7be64f3fb79457`。实施前读取了导航、样式、资产、日志模块、现有六组测试及 `.openai/hosting.json`；没有找到 AGENTS.md、业务后端、业务用户表、数据库迁移或原 RDP 源码。附件的第 1–19 节是需要实现的功能基线，不能宣称源代码中原本存在。

复用 `dist/index.html` 主导航、`app.js` 路由分发、现有 CSS 主题变量和自托管字体，新增“远程接入 · LinuxTab”。未覆盖其他模块的业务代码，未引入另一个前端框架。原资产集合是浏览器中的演示数据，不能作为真实授权来源。新远程资产提供稳定 ID 和可选 `inventoryId` 关联，必须明确登记可信端点。

因宿主没有应用认证，按附件 23 节建立最小完整认证。Sites 的 ChatGPT 私有站点访问控制与应用平台用户不同；没有把外部站点 Cookie 当成本模块可信身份，也没有无条件信任身份请求头。以后接入企业 SSO 需要可靠的主体映射，不能直接用用户名碰撞合并。

采用原方案中的 Go 管理端方向；SSH/SFTP 使用 Go 维护库实现，无另建重复身份系统的 Rust 网关。Rust Agent/采集系统不是此次远程接入附件的实现范围。

## 实际部署拓扑

同一个 HTTPS 域名提供 `dist/` 和 `/api/remote-access`。Go 服务使用 PostgreSQL；SSH/SFTP 由 Go 所属网关发起原始 TCP。Windows 连接器主动向平台发出经 TLS 验证的签名 HTTPS 请求；RDP TCP 从用户自己的 Windows 电脑发起。平台与用户电脑的网络可达性必须分别满足。

Sites 当前托管为静态 Worker，不能在该运行环境启动 Go 或原始 SSH TCP 服务。源码与页面在原仓库集成，但原托管 URL 不会因此自动获得远程后端。无已部署网关时页面明确显示不可用，不降级到 mock。

## 服务准备

1. 使用受维护的 PostgreSQL，在数据库之外保管 32 字节 AES 主密钥；生产使用 `sslmode=verify-full` 和受信 CA。不要把数据库密码写入命令历史、PR 或前端。
2. Go 版本由 `go.mod` 固定为 1.27.2。构建 `go build -o bin/infrascope ./cmd/infrascope`。原生 Linux/Windows 服务器兼容性仍需按实际部署环境验收。
3. 将 `remote-access/.env.example` 内容填写到受权限保护的环境文件；Go 不自动加载 `.env`，由 systemd、容器 secret 或进程环境注入。
4. 配置真实 `REMOTE_PUBLIC_ORIGIN=https://...`，`REMOTE_STATIC_DIR` 指向本仓库 `dist`，`REMOTE_ALLOWED_CIDRS` 显式允许授权目标网段。空列表拒绝所有目标。网关回环、自身地址、链路本地、组播和未指定地址被拒绝。远端端口只取管理员维护的资产记录。
5. 执行 `infrascope migrate`，再通过标准输入向 `infrascope bootstrap` 提交 JSON，字段为 `username`、`displayName`、`password`。密码至少 12 字节；不要使用公开示例密码。首个用户存在后 bootstrap 拒绝再次运行。
6. 设置 `REMOTE_ENABLED=true`，运行 `infrascope serve`。参考 `remote-access/deploy/nginx.conf` 和 `infrascope.service` 合入现有部署。网关无需 root；用专用 OS 用户启动。TLS 私钥、环境文件、数据库备份由管理员控制读取权限。

关闭 `REMOTE_ENABLED` 时，serve 仅提供原静态页面，远程 API 返回明确的模块禁用状态，不依赖数据库启动。migrate/bootstrap/rotate-keys 命令仍要求数据库与密钥配置。

浏览器二进制块最大 4 MiB、JSON 最大 1 MiB、WS 消息最大 64 KiB。代理设置 5 MiB 请求上限并关闭请求/响应缓冲。WS 升级和空闲超时不可省略。不要记录请求体、Cookie、设备签名、一次性附着授权或 WebSocket 内容。

## 多网关

每个网关有独立 `REMOTE_GATEWAY_ID`，共享同一应用数据库、密钥环和公开 Origin。资产端点明确绑定 gatewayId。配置 `REMOTE_GATEWAY_PEERS` 为管理员信任的网关 ID → HTTPS origin 映射（值不可带路径、凭据或查询）。网关间使用系统信任的 TLS 证书和网络 ACL，不关闭证书校验。

请求在错误节点返回 `gateway_route_required` 及目标 gatewayId，页面仅重试一次同源 `/gateways/{id}/api/remote-access/...`。该路由先校验应用登录、来源和 CSRF，再代理到已配置的受信网关；不是任意 URL 代理。WS、上传、下载都沿用所属网关路由。数据库记录会话/任务所有者；网关租约 30 秒，10 秒续约，失去租约拒绝新操作并关闭现有受控会话。重复使用活跃 gatewayId 的实例不能正常启动。重启后原 PTY 标为关闭，不假装命令仍继续运行；用户需要自行在远端配置 tmux/screen 才能获得对应持久能力。

多节点 TLS 代理、网络故障和原生 PostgreSQL 锁行为未在当前容器中完成生产拓扑验收。

## 身份、授权与凭据

平台密码 Argon2id（64 MiB、3 次、2 并行度、随机盐），浏览器使用 HttpOnly/Secure/SameSite=Strict Cookie，写请求校验 Origin 和 CSRF。登录有限速；错误不会区分不存在和密码错误。新建和管理员重置用户需首次改密；改密、退出、禁用或角色变更撤销对应登录和受控会话。

权限计算为有效个人和用户组允许动作的并集；仅匹配当前操作的授权贡献目录范围和限制，数值采用最小值并受服务器硬上限约束。没有使用授权时管理员也不能连接远程账号。审计员禁止连接和读取文件。委派检查资产管理范围、自有动作、目录、数量、大小、并发和有效期上限。账号、资产禁用和过期授权优先拒绝。

远程凭据 AES-256-GCM 加密，随机 nonce，关联 workspace/account/version 作为 AAD；主密钥由 `REMOTE_SECRET_KEYS` 版本字典注入，当前写入版本为 `REMOTE_ACTIVE_KEY_VERSION`。页面只看配置状态，不回显密码长度或秘密。更新保存的凭据不会修改远端 OS 密码。

主密钥轮换：先备份数据库及旧密钥，向所有网关注入新旧密钥，设置新的 active version，单次运行 `infrascope rotate-keys`；逐条事务解密、重新加密并追加审计。确认 `ra_secrets` 已无旧 key_version，并完成备份恢复演练后才撤除旧密钥。不能只备份数据库而丢弃密钥。

默认禁用临时凭据。若确需 SSH 临时输入，管理员必须同时设置 `REMOTE_ALLOW_TEMPORARY_SSH_CREDENTIALS=true` 和精确账号的 `credential.temporary` 授权，用户重新验证平台密码后才能提交。用户名和目标仍取账号记录；临时秘密只用于该次 SSH 认证，不入库。SFTP 的跨请求续传使用已保存的账号凭据；RDP 单机兼容输入只在明确隔离的本机模式提供。

## SFTP 行为和边界

- 列表、mkdir、rename、delete、每个上传块、提交、下载、任务控制都重新校验主体和范围；非当前用户不能通过改 taskId 查看数据。
- 文件夹选择使用目录句柄，拖放使用目录条目递归枚举，包括空目录。没有这些 API 时要求兼容桌面浏览器，不使用会丢失空目录的静默替代。没有实现自动解压上传包，不存在不受控的 ZIP 展开入口。
- 清单分批最多 500 项。每块最大 4 MiB，带 offset 和 SHA-256；已确认块幂等，恢复时重新校验远端块。临时文件同目录、O_EXCL 创建，最终校验后重命名。支持原子覆盖扩展时才允许覆盖，不支持就明确失败并保留原文件。
- 默认同名冲突需处理；可选 skip/rename/overwrite。覆盖必须授权和确认。取消不删除已完成文件。逐项失败、partial 和清理待办可追踪。
- 文件/目录 ZIP 使用 Go 流式 ZIP64，不把整个文件或包载入内存；清单有数量与深度上限。单文件响应与 ZIP 都可能在数据已开始发送后失败，必须查看任务最终状态。浏览器直接下载无法证明已落盘；支持 File System Access 时页面在写入关闭成功后单独提示。
- 实时下载不提供假暂停/Range 续传；重试重新读取源。上传浏览器关闭后不继续读取本地文件，约 60 秒后标为等待恢复。重新关联本地目录要核对路径、大小、修改时间和服务端块摘要。
- 路径验证包含边界、lstat、realpath；默认拒绝符号链接和特殊文件。SFTP realpath 与后续写入不能消除远端并发修改引发的 TOCTOU。对强隔离要求，应使用专用账号、chroot/ForceCommand 和 OS ACL。SSH shell 授权本身并不受 SFTP 页面目录范围约束。
- 部分远程写入成功后数据库或网络失败仍可能留下临时对象；每分钟进行有限重试。原授权/登录已失效时不会绕过权限删除远端文件，保留 cleanupPending，由有权限管理员检查 `.infrascope-{taskId}-{itemId}.part`。不能承诺在目标不可达或凭据已撤销时必然自动删除。

默认每用户 8 个 SSH、3 个文件任务，网关 128 个 SSH、32 个 SFTP 通道；文件通道每用户/账号 8 个；每用户文件带宽默认 16 MiB/s。账户 SSH 硬上限 32。文件大小、任务总量和深度由授权再限制。这里是保护性限额，不是经过生产容量测试的性能承诺。

## Windows OpenSSH / 受限 SFTP

在授权的 Windows 测试机上，由管理员按照 Microsoft OpenSSH Server 文档安装可选组件、启用 sshd、配置实际账号 ACL、监听端口及防火墙。平台不会自行安装软件或提升目标权限。管理员从可信控制台获取主机公钥指纹，在平台分别批准 SSH/SFTP 端点；使用服务器返回的规范路径，例如 `/C:/...`，不要猜测所有 Windows SFTP 实现的根目录格式。

Linux 受限文件账号的 sshd 示例（由目标机管理员审核后使用）：

```text
Match User transfer-only
    ChrootDirectory /srv/sftp/transfer-only
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
```

chroot 顶层应由管理员拥有且不可被该账号写入，写入子目录另行授权。Windows 的 chroot/ForceCommand 支持和路径权限要以目标 OpenSSH 版本文档及实测为准，不照搬 Linux 文件权限命令。

## 迁移和回滚

迁移只新增 `ra_` 表、索引、审计不可修改触发器及模块列，不更改原演示存储。执行前做数据库快照；用专用迁移角色执行，生产运行角色只授必要 DML，审计表只允许 SELECT/INSERT。数据库超级用户仍能破坏审计，应用触发器不能替代外部不可变审计系统。

关闭功能开关和停止网关可回退原站点；保留新增表和密钥以便审计及恢复。不要用 DROP CASCADE 回滚有真实授权/任务的数据库。恢复需要同时恢复数据库版本与对应密钥环，并在服务启动后重新建立原 SSH 连接；已经传出的文件和已建立的 mstsc 会话不能撤回。

## 已查证依赖（2026-10-17/18 UTC）

Go 1.27.2；pgx 5.11.0；x/crypto 0.58.0；pkg/sftp 1.13.11；coder/websocket 1.8.15；xterm 6.0.0、fit 0.11.0、search 0.16.0、serialize 0.14.0。测试依赖 PGlite 0.5.10 / socket 0.2.13。版本通过官方 Go proxy/npm 元数据查询，锁在 go.mod/go.sum 与 package-lock.json。浏览器运行资产自托管，MIT 许可随文件保留，无 CDN 运行依赖。

官方参考：
- https://pkg.go.dev/golang.org/x/crypto/ssh
- https://pkg.go.dev/github.com/pkg/sftp
- https://xtermjs.org/docs/guides/security/
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rdpsign
- https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew
- https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
- https://github.com/electric-sql/pglite/tree/main/packages/pglite-socket
