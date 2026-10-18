# 构建、启动与更新

## 1. 两种方式

- **容器方式**：宿主只需要 Git、Node 22+、Docker/Compose v2.24+ 和 OpenSSL。Dockerfile 在独立 Node/Go 阶段构建，运行镜像不含源码工具链。
- **原生方式**：另安装 Go 1.27.2+、Python 3；可选 Rust stable 与 C 编译器。不得依赖原开发机的 `.dev-tools/` 或 `/home/meitaolin/...` 路径。

所有命令在仓库根目录执行。依赖版本以 `package-lock.json`、`remote-access/go.mod`/`go.sum`、`telemetry-agent/Cargo.lock` 为准。Rust 使用标准 rustup stable，原开发机版本记录不能代替新环境编译验证。

## 2. 容器首次运行

```bash
npm run setup
npm run up
```

setup 生成 `.runtime/compose.env`（数据库密码、AES 密钥和配置）、`.runtime/admin.json`（随机管理员）、`.runtime/tls/`（30 天本地证书与私钥）。文件权限受限，不会上传 Git。再次执行保留已有配置，不会重置密码、数据库或加密密钥。

up 按顺序构建镜像、等待 PostgreSQL、停止本 Compose 项目的旧应用、事务执行迁移、在空用户表时通过 stdin 初始化管理员、启动应用。失败会保留数据，不能把失败当初始化成功。

Compose 的 PostgreSQL 无宿主暴露端口，放在内部网络。开发环境应用到数据库使用此内部网络；生产远程数据库应改为受信 TLS、受限角色和独立秘密管理。应用使用当前 Linux 用户 UID/GID 读取本机 TLS 文件，以非 root 运行；只读根文件系统并丢弃 capabilities。

默认为 `https://localhost:18443`，只绑定 127.0.0.1。其他机器上的 Linux Agent 无法访问这个地址。

首次使用其他端口：

```bash
npm run setup -- --port 18445
```

全新部署需要接收远端连接时，明确配置：

```bash
npm run setup -- --port 18443 --bind 0.0.0.0 --origin https://monitor.example.com:18443
```

将 `.runtime/tls/server.crt` / `server.key` 替换为匹配域名的可信证书对，核对文件权限及实际防火墙来源。示例域名不是可直接使用的服务。脚本不会自动开放防火墙或配置远程账号授权。已有部署先备份，再编辑 `.runtime/compose.env` 中的端口、origin 与 bind；再次 setup 的参数不会覆盖已有文件。

## 3. 原生编译与启动

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run build
```

输出：

```text
build/service/
├── infrascope            # Windows 构建时为 infrascope.exe
├── web/                  # 编译/复制后的自包含静态资源
├── remote-access.env.example
├── BUILD.json
└── BUILD-AND-RUN.md
```

准备 PostgreSQL、受保护的环境配置和 TLS。Go 不自动读取 `.env`；由进程管理器注入环境变量。`REMOTE_STATIC_DIR` 指向输出包 `web/` 的绝对路径；数据库连接、主密钥和 HTTPS 证书参考 `remote-access/.env.example`。依次执行输出程序的 `migrate`、`bootstrap`、`serve`。bootstrap 从 stdin 读取 `{username,displayName,password}` JSON，不通过命令参数传入密码。详细身份/网关配置见 `docs/remote-access/DEPLOYMENT.md`。

Rust 客户端：

```bash
cargo build --manifest-path telemetry-agent/Cargo.toml --release --locked
npm run package:telemetry
npm run prepare:onboarding
```

仅当前宿主平台打包；Linux/Windows 交叉包需安装对应 Rust target 和链接器，显式使用 `python3 scripts/package-telemetry.py --platform linux|windows|all`。当前打包模板仅支持 x86_64 GNU / Windows；不要将其他架构二进制误标成 x86_64。Linux 实际 libc 兼容性由构建环境和目标验证决定。

`npm run prepare:onboarding` 为本地原生开发复制公开客户端包和本地公钥证书到 `dist/downloads/`。容器运行镜像只含服务和网页，Compose 将 `.runtime/downloads/` 作为只读公开下载目录挂载。完成客户端构建与打包后执行 `npm run prepare:compose-downloads` 即可复制当前平台公钥证书与公开客户端包；不需要重建镜像。setup 会先创建下载清单，没有发布包时引导明确提示尚不可用。

原机 `npm run dev:init` / `npm run dev` 仍可复用 `.local-dev/`。全新 clone 的正式快捷入口是 setup/up；旧开发脚本不属于自动生产部署。

## 4. 测试与持续集成

- `npm test`：先生成 dist，再运行前端/Windows 连接器 Node 测试、需求结构与源码边界检查。
- `npm run test:telemetry-rust`：Rust 单元与本机采样测试。
- `npm run test:native-pg`：独立 Docker PostgreSQL + Go race，全程不读取业务数据库；镜像拉取或 C 编译器缺失会明确失败。
- `.github/workflows/ci.yml`：干净 runner 构建与以上测试，避免仅在开发机上可用。

有 Docker 和编译器不等于外部目标、RDP 桌面或生产长稳态已验收。

## 5. 更新、备份与回退

更新前备份 Compose PostgreSQL 卷的数据库快照，并安全保存 `.runtime/` 的原密钥、证书和管理员资料。数据库备份不得进入 Git。`git pull --ff-only && npm run up` 重建镜像并执行增量迁移。setup/up 不删除持久卷，不重生成现有秘密。

停止使用 `npm run down`。不要用 `docker compose down -v` 当普通停止命令；那会删除数据库卷。回退应用应保留数据库及原密钥，按迁移兼容性确认，不能直接 DROP 表恢复旧版。

公开仓库只含源码/模板/需求。日志、截图、数据库、私钥、注册状态、真实凭据、编译器缓存、安装依赖和二进制发布包都在忽略目录，重新拉取不会也不应该恢复这些私有数据。
