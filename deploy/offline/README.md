# InfraScope Linux amd64 离线部署

包含：应用镜像、PostgreSQL 镜像、docker-compose.yml 和初始化/启停脚本。目标服务器无需 Git、Node、Go、Rust、Python、npm 或外网；需事先安装 Docker Engine 与 Docker Compose v2.24+，使用有 Docker 权限的账号。预留至少 3GB 镜像/解压空间，另加实际数据库容量。

## 部署

将整个 tar.gz 复制到 Linux x86_64，解压后进入目录：

```bash
tar -xzf infrascope-offline-*.tar.gz
cd infrascope-offline-*
sha256sum -c SHA256SUMS
./start.sh --host 你的服务器IP或域名
```

默认监听 `0.0.0.0:18443`，打开 `https://你的服务器IP或域名:18443/#help`。修改首次端口用 `--port 18445`；只允许本机访问可加 `--bind 127.0.0.1`。目标网络需允许你选择的入口端口，脚本不会更改系统防火墙。

初始为匹配所填 IP/域名的自签名 HTTPS 证书。请核对后信任 `config/server-ca.crt`，或在首次启动前放入自己的匹配证书对 `config/tls/server.crt` 与 `server.key`。不要关闭证书验证。自签证书有效期 365 天，更新证书后需重启应用并更新客户端信任。

查看随机管理员：

```bash
cat config/admin.json
```

用户名为 `admin`，密码在 password 字段；不要把文件或密码上传 GitHub、发到聊天。以后重启执行 `./start.sh`，原密码、AES 密钥和数据库保留。

## 当前目录布局

```text
.
├── docker-compose.yml
├── images.tar                 # 离线镜像，仅 docker load，无在线拉取
├── VERSION.json               # 源码版本、架构、镜像 ID
├── start.sh / stop.sh / status.sh
├── config/                    # 首次启动时生成
│   ├── deploy.env             # 端口、主机名、运行 UID/GID
│   ├── app.env                # 应用、数据库连接与 AES 密钥
│   ├── postgres.env           # 数据库初始化密码
│   ├── admin.json             # 随机初始管理员
│   ├── server-ca.crt           # 可分发给采集客户端的公钥证书
│   └── tls/server.crt, server.key
├── data/postgres/             # PostgreSQL 全部持久数据（包含 18/docker）
└── logs/
    ├── app/service.log        # 应用、迁移与初始化输出
    └── postgres/              # PostgreSQL 每日日志
```

没有匿名或命名数据卷，业务数据与配置都绑定当前目录。`.env` 仅是指向 `config/deploy.env` 的本地链接，方便直接使用 Docker Compose。

```bash
docker compose ps
./status.sh
./stop.sh                     # 保留 config、data、logs
./start.sh                    # 重新启动并执行兼容迁移
```

Compose 禁止拉取镜像，所有服务使用本包加载的镜像。Web 与 API 共用一个 HTTPS 服务，数据库不映射到宿主端口。普通 Docker 引擎事件/容器启动诊断仍由 Docker 管理；应用运行日志与 PostgreSQL 日志保存在本目录。应用日志轮转可参考 logrotate.example.conf，替换实际路径并按需接入宿主 logrotate。

## 备份与更新

停服后将 `config/` 和 `data/` 一起备份；需要留存的日志一并保存。数据目录由 PostgreSQL 用户拥有，普通用户不要随意 chmod/chown，文件备份可使用 root。只有数据库没有原 AES 密钥时，已有远程凭据无法解密。

更新前先备份，再用新包中的镜像、compose 和脚本替换同名发布文件，保留 `config/ data/ logs/`。执行 `./start.sh`，不会重置现有密码或加密密钥。更改入口地址/端口时，在 `config/deploy.env` 和 `config/app.env` 同步设置并换用匹配证书。

客户端 Agent 是独立程序，使用仓库 telemetry-agent 的发布包；本离线服务包不包含目标机器身份或注册令牌。部分原监控/日志页面仍为演示，服务部署成功不代表完整产品验收。

“本机发现”当前仅验证 WSL，普通 Linux/Docker 部署会明确拒绝自动分类；请使用手工添加资产、CSV 导入或独立 Agent 注册接入。
