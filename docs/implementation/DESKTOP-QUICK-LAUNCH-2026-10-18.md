# 数据库驱动的 Windows 快捷启动

2026-10-18，Asia/Shanghai。用户希望类似 1Remote：Web 录入 Linux/Windows 服务器并存数据库，Windows 常驻客户端按快捷键调出搜索窗口并连接。

## 实际实现

- 继续使用原 PostgreSQL 资产/账号/加密凭据/授权，没有另建桌面资产库。桌面不直接连接 PG，不保存 DB 密码，不读取可复用远程秘密。
- Windows PowerShell 5.1 + WinForms 常驻托盘，默认 Ctrl+Alt+Space，Esc 隐藏；搜索名称/IP/账号/协议，250ms 服务端搜索，200 UTF-8 字节上限，截断显示提示，Enter/双击明确发起。
- Windows 面板 → 回环 Node 连接器 → Ed25519 签名 HTTPS → Go 当前绑定/授权检查 → 数据库。客户端只收白名单展示字段。
- RDP 从当前设备签发任务、精确轮询、一次性兑换并复用原 mstsc/签名/DPAPI链路。任务并发去重，不因重复Enter重复启动；后台poll不自动执行。
- SSH/SFTP 打开同平台 `/remote-workspace.html`，URL仅稳定 assetId/accountId/protocol/userId，不含凭据或令牌。浏览器必须登录配对用户，重新授权后启动真实SSH或定位SFTP，失败回到指定服务器面板。
- 登录失效、设备/浏览器绑定撤销、用户禁用、权限回收在查询/启动重检；管理员也无隐式远程授权。组织/资产只读范围不会变成远程权限。

## 本轮修复

- 配对用户与默认浏览器登录用户可能不同：catalog/本机POST/返回URL/浏览器逐层核对非秘密userId，禁止静默换身份。
- 配对在目录显示和Enter之间变化：本机再次比对请求userId和实际DPAPI配对用户，不允许调用者覆盖签名主体。
- 默认poll仅10条影响第11个快捷RDP：新增launchId精确过滤，仍严格限制当前设备。
- 目录动作过滤与网页不一致：要求同一grant包含协议、remoteAccount.use及动作，实际policy继续复验。
- 搜索包括协议/OS，按词AND匹配、统一UTF-8长度；列表最多200项不是假装全量。
- SSH失败后刷新期间换页/换身份：再次校验epoch，避免迟到错误窗口覆盖新页面。
- SSH快速链接刷新不会重复启动：请求前移除已消费intent；离开时未附着的新会话仅由同身份尝试关闭。

## 当前运行

Windows常驻客户端由 `scripts/start-windows-quick-launcher.ps1` 启动，原连接器由 `scripts/start-windows-connector.ps1` 管理。源在WSL，Windows运行副本在本人 LocalAppData/InfraScope/runtime；DPAPI配对保留，无开机启动/注册表自启动，没有修改用户快捷键配置。

已实际启动常驻进程；快捷键Ctrl+Alt+Space在独立Windows smoke测试中注册成功后释放，正式实例随后注册。根代理确认进程持续运行、日志无失败，并通过真实本机API签名取得目录：0项，非mock。现有数据库尚无有效远程账号授权，所以空列表是实况，不填示例条目。

Windows原生助手测试61项通过；WinForms/托盘/热键注册与释放smoke通过（根代理用独立4174+CtrlAltF10避免与正式实例冲突，未网络调用/未启动远端）。物理按键尚未由用户核实，不称实际快捷键操作已验收。

最终Node/Go原生PG测试见 `evidence/quick-launch-final-checks.json`；Windows证据见 `quick-launcher-windows-helpers.txt`、`quick-launcher-windows-smoke.txt`、`quick-launcher-live.json`。测试的SSH目标为隔离协议服务，RDP为签名任务夹具，不能冒充用户实机登录。

## 用户入口与未完成项

网页继续在 `https://127.0.0.1:18443/#devices` 添加服务器与系统账号，明确本人授权并核对SSH指纹；当前配对浏览器会话仍有效时快捷目录可用。新登录或会话过期需在本人Windows重新配对，不假装永久绕过登录。

这是轻量快捷启动器，不是完整1Remote替代品：Windows仍使用独立mstsc窗口，未实现内嵌多标签RDP；Linux是浏览器SSH，SFTP为现有文件工作台，不声称Linux图形桌面已实现。真实服务器SSH、文件上传下载、RDP认证/重定向尚无证据，保持未完成。
