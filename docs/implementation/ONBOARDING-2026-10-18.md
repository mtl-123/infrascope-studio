# 用户手册与 Linux 接入引导（2026-10-18）

当前本地服务新增固定导航“逐步接入 Linux”“帮助与使用手册”，首页与 Agent 策略有接入入口；原远程接入的空授权提示提供正确的 Agent 引导链接。

## 实际使用

打开 `https://127.0.0.1:18443/#help` 阅读按任务组织的教程；支持关键词搜索。引导在 `#getting-started`，登录后按四步操作：

1. 同页选择已有 Linux 资产，或填写资产名称、物理/虚拟类型、责任联系人并明确确认保存。管理员可在同页新增联系人，其他资产管理员选择既有启用联系人。新资产无 SSH/SFTP/RDP 端点，不创建远程账号与授权。
2. 选择目标在同一 Linux/WSL 或另一台 Linux。loopback 地址不允许选择远端后继续；验证 HTTPS 与 x86_64 / glibc >=2.34 后才继续。提供发布包、公钥证书及不含令牌的 host.toml 下载。
3. 按页面命令校验 SHA256、解压、生成配置、sample。明确点击后生成 10 分钟 host 令牌，在目标安全输入并执行 enroll、once、run。注册失败不会继续采集，令牌不进入命令参数、配置文件、浏览器存储或 URL。返回、离开、退出、过期时清除显示；不宣称显示清除等于服务端撤销。
4. 选择与 hostname/status 对应的 Linux Agent。每 5 秒读取本资产真实 telemetry，要求本次检查之后收到的样本、匹配 Agent、新鲜时间与 health.status=ok 才显示成功。旧样本、Windows/Docker/PVE、暂停/撤销、缺失或错误不会判成功。页面离开停止检查。

联系人与资产保存复用既有 API/权限/CSRF。两次保存不是单个事务，页面提前说明已保存记录保留；明确错误后保留联系人避免重复新增。网络中断导致结果不明确时阻止盲目重试，要求先核对已有人员/资产。刷新后重新选择已有资产继续，不自动恢复秘密。

## 文件与运行

- `dist/getting-started.js` / `.css`：引导、手册与样式；复用现有云白/深空/青岚变量。
- `dist/app.js` / `index.html`：主导航、首页入口与路由。
- `dist/remote-access.js`：复用认证、API、权限与真实指标对话框；引导模式只保留相关的内部标签。
- `scripts/prepare-onboarding.mjs`：复制明确的公开 Linux tar.gz、读取当前本地公钥证书，生成 SHA256/下载清单；绝不复制私钥、注册状态和数据库配置。输出 `dist/downloads/` 已忽略，不将 6.6MB 生成物当源码提交。
- `npm run prepare:onboarding`：本地刷新下载包和公钥证书；`dev:init` 同时调用。更换证书或发布包后应再次执行。证书属于当前本地开发配置，其他部署应提供该部署自己的可信证书。
- 静态资源由既有 Go 服务直接读取，本次无需重启或迁移数据库；没有发布托管站点或调整防火墙/监听范围。

## 验证与边界

- 新增引导与 shell 测试 14 项，验证回环地址、TOML/命令、明示确认、并发锁、人员复用、未知结果禁止重复、离开/身份变化防晚响应、旧数据不误判和令牌/定时器清理。
- 原前端 Node/VM 回归 155 项；原 6 组脚本通过。首次回归发现测试 DOM 桩缺少新增首页 banner 所需 createElement/prepend，补足 DOM 能力并增加 banner 入口断言后复测通过，未削弱产品规则。
- Chrome + 独立 PostgreSQL + HTTPS `localhost:18444`：真实填写联系人与资产、拒绝远端 localhost、从页面提取安装命令实际运行，使用网页令牌注册真实发布包 Linux 二进制，持续上报后网页确认新鲜/ok。SQL 独立核对没有创建远程账号与 grants。真实业务库未写测试资产/令牌。
- 浏览器实际下载的 `host.toml` 在 Windows Downloads 回读，地址为隔离测试 origin，CA 路径正确，无令牌。浏览器下载事件观察工具超时，不作为产品下载失败；文件落地内容独立确认。
- 请求 390px viewport 后实际 window.innerWidth 为 1036，精确 390px 尚未验证；保留限制，不称手机全量通过。默认桌面布局实际截图已保留。
- 完整证据：`evidence/onboarding-20261018/report.json`、`linux-real-upload.png`，Windows `测试截图/onboarding-20261018/help.png`。测试 Agent、隔离服务和临时数据库在结束时清理。

当前本机平台仍仅监听 loopback。引导不会自动扩大网络范围，远端 Linux 的真实部署、开机自启、PVE 与生产容量仍需单独完成。
