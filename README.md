# InfraScope

现有 SRE/AIOps、资产、网络与日志工作台，新增同仓库的真实远程接入模块。

- `dist/`：原界面、主题、导航；`remote-access.js` 为真实远程操作入口，不使用演示资产 IP 或模拟响应。
- `remote-access/`：Go 管理接口、账号授权、SSH/SFTP 网关、PostgreSQL 迁移与隔离测试。
- `windows-connector/`：每位 Windows 用户电脑上的 Node + Windows PowerShell 连接器，无业务运行时 npm 依赖。
- [部署与运维](docs/remote-access/DEPLOYMENT.md)
- [API 和消息契约](docs/remote-access/API.md)
- [权限和功能验收矩阵](docs/remote-access/ACCEPTANCE.md)
- [Windows 连接器](windows-connector/README.md)

当前托管站点为静态 Sites；Go/原始 SSH TCP 网关不能在该静态托管进程运行。需在具备实际路由的服务器部署同一仓库的 Go 服务，并通过同源 HTTPS 提供页面和接口。已有监控/日志页面仍然是交互演示；新增远程模块没有将它们冒充为生产采集数据。

```sh
npm ci
npm run vendor:terminal
npm run test:existing
cd remote-access
go build -o bin/infrascope ./cmd/infrascope
```

正式启动前完成部署文档中的数据库、外部密钥、首个管理员和网络配置。仓库不包含默认管理员、目标密码、私钥或可直接连接的示例机器。
