# WSL 本地开发

开发目录为 `/home/meitaolin/projects/infrascope-studio`。全部业务编译、Node/Go 测试、数据库和服务运行在 Ubuntu WSL2；浏览器在 Windows 验证访问。没有更改在线 Site。

```bash
cd /home/meitaolin/projects/infrascope-studio
source scripts/wsl-env.sh
npm ci --ignore-scripts --no-audit --no-fund
npm run dev:init
npm run dev
```

当前打开 `https://127.0.0.1:18443/#devices`，旧HTTP18080只跳转。随机本地管理员保存在 `.local-dev/admin.json`，仅本机开发使用，不公开展示密码。初始化不会自动添加或连接真实主机。选择“添加服务器并连接”一次填写目标与凭据，明确确认才保存和授权；测试资产不表示真实远程可用。

`Ctrl+C` 关闭 Web 服务，`npm run dev:stop-db` 停止本仓库的数据库容器并保留数据。不要删除 `.local-dev/config.json` 后重建密钥，已有凭据可能无法解密。此开发配置使用 loopback HTTP，不得作为生产部署；生产继续按 `docs/remote-access/DEPLOYMENT.md` 配置 HTTPS、密钥、角色和网段。

## 可重复验证

```bash
source scripts/wsl-env.sh
npm run test:existing
npm run test:connector
npm run test:asset-form
npm run test:unified-assets
npm run test:import-discovery
npm run test:asset-remote
npm run test:server-onboarding
npm run test:quick-launch
npm run test:full-qa-regression
npm run test:gates
npm run test:requirements
npm run check:requirements
npm run test:native-pg
cd remote-access && go vet ./... && go build ./cmd/infrascope
```

P2 本地备份恢复检查：暂停本仓库 Web 进程以避免后台租约持续写入，保持开发 PostgreSQL 运行，在仓库执行 `npm run test:p2-recovery`。脚本只读取本仓库开发数据库，在独立无外网临时容器还原并比对逐表摘要，结束清理该临时容器；不会清空源库，也不把该检查称为生产灾备完成。若源数据在备份前后发生变化会拒绝，不得忽略后直接报告通过。

主导航“设备与使用人”和远程“资产与账号”现共用真实 `/api/v1/assets` 与同一 ID。“组织与人员”为真实手工联系人；管理员可配置资产组只读范围，范围不授予远程账号使用权。其他演示模块尚未完成生产数据接入。

P2 最新还包含“导入与发现”“组织范围”。CSV 先预览、明确选择行后创建，预览不写资产；取消只影响剩余候选，已创建资产保留。本机发现仅覆盖当前 WSL Linux，不扫描网段、不安装 Agent；其他系统/外设待验证。组织层级仅分类，直接成员只读直接绑定资产，不继承远程访问。执行 `npm run dev:init` 应用 001–005 增量迁移，升级前保留私有数据库备份。

远程操作修正后迁移为 001–006，详见 `REMOTE-ASSET-WORKFLOW-2026-10-18.md`。从每台资产的“连接 / 文件”继续配置，不需要在空白远程页猜步骤。开发网关默认不允许任何目标；只在确定授权目标网段后，在启动 `npm run dev` 的同一 WSL shell 显式设置 `REMOTE_ALLOWED_CIDRS`（逗号分隔），启动器现会保留该值。不要设置 0.0.0.0/0 作为省事替代。此配置不会安装目标SSH、开放目标防火墙或授予账号权限。

HTTPS和本人Windows连接器现已真实配置，见 `HTTPS-CONNECTOR-ONBOARDING-2026-10-18.md`。证书只信任当前Windows用户，Windows Chrome已验证；内嵌浏览器曾报不信任，勿绕过。证书30天有效，过期应显式换证和更新信任，不静默禁TLS。Windows连接器启动用仓库 `scripts/start-windows-connector.ps1`，保持DPAPI配对；该脚本不自动初始化签名或接受UAC。目标GUI、认证、文件与重定向仍须实机验证。

Windows快捷搜索客户端：运行 `scripts/start-windows-quick-launcher.ps1`（Windows PowerShell），默认 Ctrl+Alt+Space，Esc隐藏，托盘退出。只从平台读取当前配对用户获授权目录，不直接连接数据库；RDP调用mstsc，SSH/SFTP打开授权工作台。详见 `DESKTOP-QUICK-LAUNCH-2026-10-18.md`。本轮未安装开机自启动。

全模块验收新增 `npm run test:isolated-recovery`：独立合成PG/应用恢复与密钥轮换测试，不停止或读取liveDB。详见 `FULL-MODULE-QA-2026-10-18.md`。精确断点、真实浏览器传输、外部目标与生产容量仍需各自证据，不能以自动套件绿色替代。

原生 PG 测试使用精确 digest `postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`，不触碰既有数据库容器。要求 Docker、Go、CGO 与 C 编译器可用。缺任一条件应记录阻塞，而不是关闭 race 或用 PGlite 冒充原生 PG。

本机没有系统 GCC，因此在 `.dev-tools/gcc` 用户目录解包 Ubuntu 软件仓库的 gcc-15/cpp-15、libgcc-15-dev、libc6/dev、linux-libc-dev、libisl23、libmpc3；未运行 sudo/系统安装。包装器仅影响 `source scripts/wsl-env.sh` 的 shell。换机器应使用该机器受控安装的编译器或重新准备本地工具链。

下载需要代理时，可在当前 shell 设置已存在的本机代理，不写入代码或全局配置：

```bash
export HTTPS_PROXY=http://127.0.0.1:7897 HTTP_PROXY=http://127.0.0.1:7897
export NO_PROXY=127.0.0.1,localhost,::1
```

## 证据边界

矩阵是 `docs/requirements/infrascope/05_需求追踪矩阵.csv`。每阶段保存失败、修复、复测及代码摘要到 `docs/implementation/evidence/`。原文需求包、旧报告和单个绿色测试都不是整条 REQ 的实机验收。

当前监控、网络、日志、SRE/AIOps 页面仍属原交互演示；真实实现入口位于远程接入模块。不得把演示资产自动导入信任域，或将本地数据库/测试服务等同用户目标机器。
