# InfraScope Windows 用户端连接器

本目录属于 InfraScope 原项目，不是独立的监控演示。连接器必须在操作者自己的交互式 Windows 登录会话中运行。默认 controlled 模式，只接受当前平台登录绑定的授权任务。中央 Linux/Windows Web 服务器不会替用户运行 mstsc。

## 启动与配对

前提：Windows 自带 Windows PowerShell 5.1、mstsc.exe、rdpsign.exe，Node.js 22+。本次 Node 语法和 HTTP 测试运行在 Linux Node 24.19.0，Windows 执行尚未验收。运行无需业务 npm 依赖。

```powershell
cd C:\InfraScope\windows-connector
$env:INFRASCOPE_PLATFORM = 'https://你的实际平台域名'
$env:INFRASCOPE_MODE = 'controlled'
node .\server.mjs
```

浏览器打开 `http://127.0.0.1:4173`。如同一电脑有多个交互用户，各自使用自己的端口（`$env:PORT`）及私有 Windows 账号空间，不把共享桌面当作多人隔离。

在平台“我的 Windows 设备”重新验证平台密码并生成一次性配对码，在本人连接器页面输入配对码和设备名称。挑战有效 120 秒、消费一次，绑定平台用户、平台登录会话、批准的平台 Origin 和 Windows SID 摘要。设备 Ed25519 私钥仅在本机生成，通过 DPAPI CurrentUser 保护后保存在当前用户 LocalAppData。不把长期设备私钥传给平台。

平台选中授权资产和远程账号，再明确选择当前浏览器绑定且在线的设备、资源选项，签发 60 秒启动任务。连接器仅出站访问启动时配置的 HTTPS origin，验证系统 TLS 信任，不接受任意平台地址；签名请求包括方法、路径、时间、nonce 和请求体 SHA-256。设备在本地页面显示目标、用户名与选项，用户确认后才兑换任务。

任务兑换在数据库事务中复核用户、原平台登录、账号、凭据版本、资产版本、授权策略、设备绑定、TTL 与消费状态。浏览器不取得持久远程密码；设备只在受认证 HTTPS 响应中短暂取得所需凭据，并通过 stdin 传给 PowerShell，秘密不进入命令行或 RDP 文件。

## 签名初始化

只读检查：

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\launcher\launch-rdp.ps1 -SelfTest
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\launcher\setup-rdp-signing.ps1 -Mode Status
```

页面“首次启用”明确确认后，才创建/复用 `CN=Pulse RDP Launcher` 的当前用户不可导出私钥证书，在 CurrentUser/Root 和 TrustedPublisher 安装公钥，并通过 Windows UAC 请求加入机器发布者信任策略。现有策略条目保留。不能关闭 UAC、远端证书认证或企业策略。

支持新版 TerminalServer.admx 的 SHA-2 策略时使用 `sha256:` 策略指纹；rdpsign 仍使用证书查找 Thumbprint。状态与启动均要求证书剩余至少 30 天，临近到期重新初始化。Status 不创建证书、不修改注册表。证书、机器策略和真实签名兼容性必须在目标 Windows 版本实际验证。

UAC 等待超过 30 秒会报告超时；已经写入的用户公钥信任可能保留，提权子进程也可能稍后完成。重新运行只读 Status 核实，不能把超时解释为“所有系统更改都已回滚”。不会自动删除旧证书或与本项目无关的策略。

## 凭据、临时文件和状态

使用 CredWriteW/CredReadW/CredDeleteW，临时文件包含全部 18 个 RDP 设置，UTF-16LE 保存，签名成功后才启动可见 mstsc。HTTP 首次结果不等待 30 秒清理。started 表示进程存在，不代表网络或远端认证成功。

同一 Windows 用户的 `TERMSRV/host` 不按账号或端口隔离。本连接器通过用户/目标互斥锁拒绝重叠注入，已有 TERMSRV 凭据不会被覆盖。需要用户自行管理已有凭据，或使用被明确授权的交互提示模式。无关 mstsc 不会被关闭。

临时凭据约 30 秒后清理；清理检查独有 marker、用户名、LastWritten 版本，发现外部改写或无法确认所有权时保留并报告失败。原生 Credential Manager 没有原子的 compare-and-delete，应用锁不能阻止其他程序的竞争；本实现不声称完全消除外部并发风险。

租约记录不含密码，在私有 LocalAppData 中记录本次文件和所有权元信息；正常退出及重启尝试回收过期残留。若在 CredWrite 与 LastWritten 持久化之间崩溃，不能确认版本时不自动删除，需用户核实。RDP 文件也仅删除符合本次 ID 和临时目录的路径。

Windows CredentialBlob 最多 2560 字节；因此超过这个 UTF-16LE 上限的密码提前拒绝，即使原型表单的 2048 字符上限还未达到。密码保持原样不 trim。字符串内存由 JavaScript/.NET 管理，清空变量不能保证所有内存副本即时清零。

用户控制、可调试或拥有管理员权限的 Windows 电脑不能保证永远无法提取下发凭据。撤销平台授权不能可靠强制结束已建立的远端 RDP 会话，也不能撤回已复制文件。本项目不提供浏览器内 RDP、录像或远端强制下线。

## 明确隔离的单机兼容模式

只在需要本机自由目标输入时显式启动：

```powershell
$env:INFRASCOPE_MODE = 'standalone'
node .\server.mjs
```

此模式保留地址/端口拆分、域/本地/UPN 账号、密码显隐、四个独立开关、全部/指定盘符、IPv6 摘要、偏好键 `rdp-access-profile-v1`、签名与可见 mstsc 流程。密码、令牌、任务授权不入 localStorage。单机模式不是平台授权通道，不能将它暴露到局域网。controlled 模式旧 `/api/rdp/connect` 只接受 launchId + confirmed，拒绝自由目标和凭据字段。

## HTTP 契约

所有请求验证真实 socket 回环地址、Host 白名单以及浏览器 Origin/Sec-Fetch-Site。GET `/api/local-token` 返回本进程随机 64 位十六进制 token；其余 API 要求 `X-Pulse-Token`。token 只保留在页面内存，重启更换。不允许跨站 CORS。

| 路径 | 方法 | 功能 |
| --- | --- | --- |
| `/api/local-token` | GET | available、token、mode |
| `/api/rdp/signing-status` | GET | 只读证书及策略状态 |
| `/api/rdp/setup-signing` | POST | 用户确认后的初始化，可能 UAC |
| `/api/rdp/connect` | POST | controlled 任务确认；或显式 standalone 完整配置 |
| `/api/status` | GET | 配对、设备心跳、待确认任务和本机启动/清理记录 |
| `/api/pair` | POST | challenge + name，绑定当前 Windows 用户 |

元数据 JSON 上限 16 KiB。缺令牌/错误来源 403，字段错误 400、媒体类型 415、超限 413，非 Windows 启动 501。过程令牌和平台设备认证是两个独立机制。静态文件只从 public 根读取，目录不列出。

## 更新与卸载

停用并撤销设备、等待本次临时清理结束后更新同仓库连接器源码，重新运行自检/配对。当前没有商业代码签名安装器，不声称已注册自定义 URI 或安装系统服务。

停止进程后删除连接器目录及本人 LocalAppData/InfraScope 中的 DPAPI 配对文件，可取消本机配对。先检查 leases 残留记录。证书/信任/策略为系统状态，卸载前核对是否仍用于已签名文件，只由管理员删除确认属于本项目的具体条目，保留其他企业证书和发布者。
