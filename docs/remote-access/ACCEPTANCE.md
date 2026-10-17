# 功能与验收对照

结论：已在原 InfraScope 仓库实现真实后端和客户端链路，隔离集成测试通过；不能宣称已完成所有真实环境端到端验收。当前没有可操作的 Windows 桌面、用户授权的真实 Linux/Windows/OpenSSH/RDP 目标或生产 PostgreSQL/HTTPS 网关。原静态托管环境不能运行 Go/SSH TCP。浏览器预览运行器受容器挂载限制，未获得真实界面截图，也未完成浏览器交互验收。

此文档将“实现存在”“已执行的验证”“未验证”分开。没有向示例 IP 或用户生产设备发起连接，没有发送真实企业通知或邮件。

## 验证证据

| 类别 | 本次结果 | 证据 |
| --- | --- | --- |
| 原项目回归 | 六组测试通过 | `test-existing.txt`，原 tests/ 目录 |
| Go 模块与加密/路径/schema | 3 个测试通过 | `core_test.go`，`test-go.txt` |
| Go 真实协议隔离集成 | 5 个测试通过，包含 `-race` | `integration_test.go`，`test-go.txt` |
| 本机 Node 连接器 | 4 个测试通过，含真实 loopback HTTP | `windows-connector/tests/`，`test-connector.txt` |
| JS 语法 | remote-access.js、连接器 server/public app 通过 | `test-static.txt`，node --check |
| PowerShell 语法 | 3 个脚本解析通过 | Linux PowerShell 7.6.6 AST，`test-powershell.txt`；不是 Windows PowerShell 5.1 执行结果 |
| 数据迁移 | 每个隔离用例连续执行两次，成功 | 同一 PostgreSQL SQL 迁移、PGlite PostgreSQL 引擎；不是原生 PG 服务运维验证 |
| 依赖检查 | npm audit 0 已报告漏洞；govulncheck 已调用符号/导入包 0 | x/crypto 模块包含未使用的 openpgp 告警 GO-2026-5932，不等同整库没有公告 |
| HTML 静态引用 | 无重复 ID、引用的本地脚本/样式存在 | `test-static.txt`；原首页、新窗口页、本机连接器页，不是布局/可用性测试 |

隔离目标是测试代码中的真实 Go SSH 服务、真实 PTY `/bin/sh` 和 pkg/sftp 服务，通过 TCP、SSH、HTTP/WebSocket 实际传输；文件实际写入隔离临时目录，并读取比较、解压 ZIP 校验。它不是 WebSocket echo，也不是生产接口内的 mock 分支。但它不是独立目标主机上的 OpenSSH，不能替代真实系统兼容性和网络故障测试。

PGlite 使用 PostgreSQL 引擎的 WASM 版本，通过其官方 socket 包接入 Go pgx。测试使用单连接和 describe_exec 规避该适配器的 prepared-statement 多连接限制。3 用户的 6 个 SSH/PTY 同时保持，但数据库事务由该测试数据库串行处理；原生 PostgreSQL 多事务争用、HA、磁盘持久性没有通过此项测试得到证明。

## 第 0–35 节对应实现

| 附件节 | 实现位置 | 已执行验证 / 未验证 |
| --- | --- | --- |
| 0 集成优先级 | 原 dist 菜单/主题，remote-access/，本同仓库连接器 | 原 6 组回归通过；没有另建独立演示项目 |
| 1 真实 RDP 链路 | windows-connector/server.mjs、launcher/launch-rdp.ps1 | 代码与协议实现；mstsc 真实 GUI、远程认证未验证 |
| 2 技术栈/目录/命令 | root package-lock、remote-access/go.mod/go.sum、连接器 package.json | Go 编译、Node 检查；连接器无业务运行时依赖 |
| 3 完整中文表单/DOM ID | windows-connector/public/index.html | 静态 ID、资源引用校验；实际浏览器交互未验证 |
| 4 字段/默认值 | public/index.html、public/app.js、protocol.mjs | 服务端配置单元测试；四开关真实 Windows 效果未验证 |
| 5 地址和 IPv6 拆分 | public/app.js | 实现；浏览器 paste/blur 事件未实机验收 |
| 6 密码显隐/磁盘范围 | public/app.js、protocol.mjs | 盘符规范化/拒绝路径测试通过；点击交互未验证 |
| 7 双端校验 | protocol.mjs、public/app.js、launch-rdp.ps1 | 字段/布尔/范围/长密码负例通过；Windows stdin Unicode 未实测 |
| 8 非秘密偏好 | public/app.js，固定键 rdp-access-profile-v1 | 仅 standalone 保存白名单字段；浏览器存储故障交互未验证 |
| 9 状态与初始化 | public/app.js、setup-rdp-signing.ps1 | 状态真实取 API；证书/UAC 部分完成与重试未实测 |
| 10 连接请求反馈 | server.mjs、launch-rdp.ps1 | 真实 PID 由 Windows 进程返回的代码已实现；当前无 Windows PID 证据 |
| 11 本机 HTTP 契约 | server.mjs、protocol.mjs | loopback、Host/Origin、令牌、404/405/501、MIME/CSP 测试通过 |
| 12 子进程通信 | server.mjs powershell() | stdin JSON、UTF-8 decoder、首次结果/超时/清理回调；Windows 子进程未执行 |
| 13 RDP 文件/凭据 | launch-rdp.ps1 | 18 设置、CredWriteW、UTF-16LE、rdpsign、mstsc；仅语法检查 |
| 14 签名证书/信任 | setup-rdp-signing.ps1 | 代码和语法检查；CurrentUser/My/Root/TrustedPublisher 未实际修改 |
| 15 发布者策略/UAC | setup-rdp-signing.ps1 | HKCU/HKLM 合并、SHA-2 检测、InstallPolicy；真实 UAC/策略未验证 |
| 16 错误和限制 | 客户端、API.md、连接器 README | 不把启动当登录，不把清理当强制断开；真实系统错误需实机补验 |
| 17 外观/响应式 | 复用宿主主题；连接器 styles.css | 源码存在，320/520/780px 和屏幕阅读器未测试，无效果图冒充验证 |
| 18 必需安全强化 | protocol.mjs、DPAPI、DB nonce/绑定、输入租约 | HTTP/设备防重放、越权负例通过；Credential Manager 外部竞争无法完全消除 |
| 19 旧功能验收 | 本表和 Windows 手工验收步骤 | 静态/隔离部分执行；所有真实 Windows 项仍未验证 |
| 20 交付 | README、DEPLOYMENT、API、ACCEPTANCE、原仓库源码 | 当前源代码集成；生产后端部署尚未完成 |
| 21 统一资产/协议 | assets.go、ra_assets/endpoints、资产页面 | 创建虚拟 Linux 资产、服务端搜索/分页及独立协议通过；真实 Windows/VM 网络未验证 |
| 22 宿主接入/开关/依赖 | http.go、main.go、dist/app.js、锁文件、deploy/ | 原回归、语法/构建、迁移通过；生产 HTTPS/WSS 未验收 |
| 23 多人身份 | auth.go、core.go、ra_users/groups/login_sessions | 3 用户、强制改密、禁用后旧登录失效、权限隔离通过 |
| 24 多账号/秘密 | accounts/credential API、core.go、keys.go | 加密 AAD/篡改拒绝、凭据元信息、主密钥轮换通过；真实私钥目标兼容性未测 |
| 25 精细分配 | assets.go grants、policy()、grantWizard | 用户/组撤权、只读 API 禁写、跨 workspace 通过；批量 UI 现场未验收 |
| 26 LinuxTab | dist/remote-access.js、remote-workspace.html、xterm 本地依赖 | 单写租约通过协议测试；4 标签/2 真实浏览器窗口、中文 IME、vim/top 未验证 |
| 27 SSH 生命周期 | ssh.go、routing.go、lease.go | 真实 PTY、stty 尺寸、6 并行会话、接管和用户禁用通过；多网关生产故障测试未执行 |
| 28 文件和目录 | sftp.go、filesView、runUpload/download | 真写入/内容校验、中文、空文件/目录 ZIP、改名/递归删、符号链接拒绝通过 |
| 29 任务/恢复/资源 | sftp.go、budgets.go、传输页面 | 真实 offset 恢复、远端篡改拒绝、分块摘要元数据、重放幂等、冲突 partial/rename 通过；磁盘满/生产容量未测 |
| 30 用户电脑 mstsc | rdp.go、server.mjs、3 个 PS 脚本 | 设备配对、一次消费、nonce 重放、撤销通过；两台 Windows 实机启动未验证 |
| 31 Windows 文件能力 | 统一 SFTP 管道 + RDP 磁盘设置 | Linux 隔离 SFTP 管道通过；Windows OpenSSH 和 tsclient 双向复制未验证 |
| 32 数据和契约 | 迁移、API.md、各 handler | 迁移幂等、真实 API 集成通过；DB 备份还原/生产角色授权未演练 |
| 33 审计/观测 | ra_audit_events、guard、health、keys/routing | 审计落库和无秘密响应被测试链路使用；不可变外部审计/专业安全认证未声称实现 |
| 34 完整验收 | 8 个 Go、4 个 Node、6 组原回归 | 部分闭环已通过；真实环境未满足，不能标为全部验收通过 |
| 35 最终集成 | 全部代码在已有仓库，原页面继续可用 | 无新项目；部署与实机验收阻塞项如下 |

## 权限矩阵

| 能力 | 平台管理员 | 资产管理员 | 普通使用者 | 审计员 |
| --- | --- | --- | --- | --- |
| 用户/用户组管理 | 是，敏感操作重新认证 | 否 | 否 | 否 |
| 资产/账号管理 | 当前 workspace | 自己管理范围 | 否 | 否 |
| 设置/清除远程秘密 | 管理范围 + 重新认证 | 管理范围 + 重新认证 | 否 | 否 |
| 查看/导出明文秘密 | 未开放此 API | 未开放 | 未开放 | 未开放 |
| 分配账号 | 明确资产/账号/动作/期限 | 不超过自身可委派范围 | 否 | 否 |
| SSH/SFTP/RDP 使用 | 也需要有效具体授权 | 也需要有效具体授权 | 有效具体授权 | 禁止 |
| SFTP 读写和删除 | 每个操作独立授权及路径范围 | 同左 | 同左 | 禁止 |
| 剪贴板/磁盘映射 | 独立授权 | 独立授权 | 独立授权 | 禁止 |
| 本人连接器配对/撤销 | 是，重新认证 | 是，重新认证 | 是，重新认证 | 否 |
| 查看/终止他人 SSH | 是，工作空间范围 | 否 | 否 | 否 |
| 审计元数据 | 是 | 否 | 否 | 是 |

菜单不是权限边界，所有相应 API 再次授权。RDP 的权限只控制本次平台交付/启动参数，不能保证用户无法在原生 Windows 提示中使用其他账号。

## 明确尚未完成的验收和环境限制

这些不是“未来功能计划”，而是当前不能签字通过的交付限制。

1. **真实部署未完成。** 当前项目的静态 Sites 发布能力无法运行 Go/SSH TCP，也没有提供可部署服务器、生产 PostgreSQL、TLS 域名或可信网关地址。新入口在现有静态站点会明确显示网关不可用。不能把页面已发布写成后端上线。
2. **真实 Windows 端到端未完成。** 无交互式 Windows 桌面和授权 RDP 测试目标，未执行 UAC、证书/策略写入、Credential Manager、真实 rdpsign、可见 mstsc、磁盘/剪贴板重定向、30 秒清理和两设备并发。PowerShell 7 Linux AST 不能证明 Windows PowerShell 5.1 兼容。
3. **真实浏览器验收未完成。** 预览运行器报 `bwrap: Can't mount proc on /newroot/proc: Operation not permitted`，没有绕过其隔离。多窗口、分屏拖动、IME、vim/top、拖放目录、系统文件选择器、CSP 和无障碍仍需实际浏览器测试。
4. **原生目标和数据库验证未完成。** 当前环境缺少可用的非 root PostgreSQL 服务权限/容器运行时，以及授权目标机。Go SSH/SFTP 隔离服务器证明协议和磁盘链路，不证明 Windows OpenSSH、各 Linux 发行版或多实例 PG 事务语义全部兼容。
5. **容量和故障注入未完成。** 未进行大文件/超大单目录内存、生产并发、弱网、网络分区、磁盘满、真实断电和多网关租约压力验收。目录内容元数据先 ReadDir 再分页，需实测超大单目录；文件内容本身分块/流式。
6. **应用级边界。** SFTP 根目录不能约束 SSH shell；TOCTOU 需远端 chroot/ACL。失效凭据/授权不会被后台清理绕过，残留可能需管理员处置。已建立的 mstsc 不是受控代理会话，不能承诺即时强制下线、录像或用户本机绝对密码保密。
7. **列表范围。** 资产管理和分配向导支持服务端搜索及每页 100 项分页。授权/会话/审计页面显示有界记录集合，当前不提供无限历史全量导出；现有限额见 API.md。

第 1–5 项是尚缺的运行/验证条件；第 6–7 项是明确的应用与展示边界，不能把它们解释为无限容量或已完成生产验收。

## 真实环境闭环验收步骤

使用隔离测试账号和可回滚测试机器，不在聊天中发送生产密码。

1. 在可部署服务器导入环境与密钥，migrate 连续执行两次，bootstrap 创建管理员，HTTPS 进入原首页及远程菜单。
2. 建立 A/B/C 三个平台用户和一个组；登记真实 Linux、Windows 和一个 VM，至少一台资产有两个不同 OS 账号；核实主机指纹并分别批准 SSH/SFTP。
3. 分配只读与读写账号，验证 A 无法读取 B 的资产/账号/session/task/device；测试到期、组移除、用户禁用、凭据轮换和重新登录。
4. 每人至少 2 个 SSH + 1 个文件任务；A 额外达到 4 标签、2 真实窗口，验证控制租约、拖动比例、焦点、中文输入、Ctrl+C、vim/top、粘贴预览、断线恢复及网关重启。
5. 上传含空格/中文/零字节/空目录/嵌套的大目录，在目标机独立计算 SHA-256；测试同名三策略、取消单项、pause/reselect/resume、篡改临时文件、源文件变化、磁盘满。下载 ZIP 后独立解压比较。
6. 两名用户各自 Windows 电脑启动连接器、配对、核对目标设备；本人确认 UAC，检查公钥信任与原有策略未丢失。测试已有 TERMSRV 凭据、同目标并发、签名失败、断电残留。
7. 点击平台 RDP，在本人电脑看到真实 mstsc。确认远端登录后分别验证剪贴板、指定/全部磁盘、全屏/多显示器；通过 tsclient 双向复制嵌套目录，核对文件摘要。约 30 秒后核对本次凭据/文件清理及平台反馈，其他凭据和会话保持正常。
8. 配置 Windows OpenSSH/SFTP 后重复网页目录上传下载。测试错误平台 TLS、离线设备、错误设备签名、重复/过期任务、撤销后兑换拒绝。
9. 以真实 PostgreSQL 执行备份恢复、主密钥轮换、网关多实例/网络分区测试，记录环境、版本、并发、延迟、CPU/RSS、错误率和残留回收结果，再决定是否可上线。

## 可复现自动命令

```sh
npm ci
npm run vendor:terminal
npm run test:existing
node --check dist/remote-access.js
node --test windows-connector/tests/*.test.mjs
# INFRA_GO 可指定已安装的 Go 绝对路径；默认使用 PATH 中的 go。
node scripts/test-remote.mjs
cd remote-access
go build ./cmd/infrascope
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

若验证原生 PostgreSQL，使用专属隔离测试数据库设置 `INFRA_TEST_DATABASE_URL` 再运行 `go test -race -count=1 -v ./...`；禁止把测试运行在生产数据库。测试会创建 `ra_` 表和隔离工作空间记录。
