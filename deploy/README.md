# 部署资料入口

- 仓库根 `Dockerfile`：从锁文件构建 Node 前端与 Go 服务，生成非 root 运行镜像。
- 仓库根 `compose.yaml`：单机 PostgreSQL + HTTPS 服务；用 `npm run setup` / `npm run up`，具体说明在 `docs/development/BUILD-AND-RUN.md`。
- `remote-access/deploy/`：原生 systemd / Nginx 模板；需按实际输出路径和环境配置调整。
- `telemetry-agent/deploy/`：Linux systemd / Windows 前台采集启动模板，运行身份和自启需目标机验证。
- `windows-connector/launcher/`：Windows 本机连接器与快捷启动代码。

这些是部署模板和本地构建入口，不包含服务器私钥、固定管理员密码或目标凭据。生产部署需自行配置可路由 HTTPS、数据库与密钥备份、角色和网络范围。
