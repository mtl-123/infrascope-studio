# InfraScope 源码与需求

这是完整的本地应用源码仓库：Go 服务 + 原生 HTML/JavaScript 前端 + Rust 采集客户端 + Windows 连接器。源码、需求、构建产物与本机运行数据分别管理。

## 按用途找文件

| 目录 | 内容 | 是否提交 Git |
| --- | --- | --- |
| `web/` | 前端源码、样式、字体；修改页面从这里开始 | 是 |
| `remote-access/` | Go 服务、身份/资产/SSH/SFTP/采集 API、数据库迁移、后端测试 | 是 |
| `telemetry-agent/` | Rust Linux/Windows 主机 Agent、Docker/PVE Collector 源码及模板 | 是，排除 target |
| `windows-connector/` | Windows RDP 连接器与快捷客户端源码 | 是 |
| `docs/requirements/infrascope/` | PRD、架构契约、187 项需求工作矩阵和原始需求 | 是，唯一需求入口 |
| `docs/user-guide/` | 面向使用者的操作手册 | 是 |
| `docs/development/`、`deploy/` | 构建、运行、更新和部署说明 | 是 |
| `docs/implementation/` | 按日期记录的历史实施说明，不作为当前构建入口 | 是，排除原始运行证据 |
| `docs/verification/` | 验证摘要与证据存档边界 | 是 |
| `scripts/`、`tests/`、`.github/` | 构建脚本、测试、持续集成 | 是 |
| `dist/`、`build/`、`release/` | 生成的网页、服务包和发布二进制 | 否，可重新构建 |
| `.runtime/`、`.local-dev/`、`.dev-tools/` | 私有配置、密钥、数据库、原开发机工具链 | 否，不要上传 |

`dist/` 已改为生成目录，不能再直接编辑。前端源码现在统一放在 `web/`；`npm run build:web` 生成页面及锁定版本的 xterm 依赖。

## 拉取后构建并运行（Linux / WSL 推荐）

准备 **Git、Node.js 22+、Docker Engine + Compose v2.24+、OpenSSL**。Docker 构建服务时无需在宿主安装 Go/Rust。

```bash
git clone git@github.com:mtl-123/infrascope-studio.git
cd infrascope-studio
npm run setup
npm run up
```

打开 `https://localhost:18443/#help`。首次为自签名证书，应核对并显式信任 `.runtime/tls/server.crt`，也可替换成自己的可信证书；脚本不自动修改系统信任或禁用校验。

随机管理员用户名和密码在 `.runtime/admin.json`，只在本机查看。数据库、密钥和管理员资料需要一起备份；不要在下一次拉取后删除 `.runtime/` 重新生成。

```bash
# 后续更新，升级前先备份数据库与原密钥
git pull --ff-only
npm run up

npm run status
npm run logs
npm run down  # 停止容器，保留数据库卷与本机配置
```

初始化默认只绑定本机。若 18443 被占用，首次执行 `npm run setup -- --port 18445`。远端主机接入、外部域名和生产部署见 [构建运行手册](docs/development/BUILD-AND-RUN.md)。

## 原生构建与测试

宿主另需 **Go 1.27.2+、Python 3**；构建采集客户端另需 Rust stable / Cargo 和 C 工具链。

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build       # build/service/：服务程序、网页、配置示例
npm test            # 前端/连接器、需求结构和源码边界
npm run build:all   # 再构建 Rust 三个采集客户端
npm run test:telemetry-rust
npm run test:native-pg  # Docker 原生 PostgreSQL + Go race；需要 C 编译器
```

详细说明：[构建与运行](docs/development/BUILD-AND-RUN.md) · [操作手册](docs/user-guide/使用手册.md) · [需求索引](docs/requirements/README.md) · [模块当前状态](docs/STATUS.md)。

当前属于部分实现：资产、采集与远程控制面有真实接口，部分监控/日志/告警页面仍为演示；完整产品、目标实机、自启和生产容量尚未验收。历史报告中的本机绝对路径仅用于记录，不是新机器的构建依赖。
