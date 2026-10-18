# Rust 采集客户端增量交付与测试（2026-10-18）

## 范围与结构

在既有 WSL 项目实现三个 Rust 二进制：Windows/Linux 主机 Agent、Docker Collector、PVE Collector。复用已有 Go 身份/权限、资产/责任关系、HTTPS 服务和 PostgreSQL，不另建孤立后台，不向客户端暴露数据库密码。原导航“Agent 策略”改为真实资产注册、指标与版本回执页面，沿用原主题。

主机实现 CPU 总体/逻辑核数、内存、swap、挂载容量、网卡累计计数与连续差分、uptime/boot time。Docker 实现只读 Engine inventory/stats、Compose 分组、停止/部分失败与截断状态。PVE 实现只读 HTTPS token API 的节点/QEMU/LXC 采集，但没有真实集群验证；VM 内部指标需另装主机 Agent。

服务端新增迁移 008（注册、身份、nonce、样本四表），一次性注册与同密钥重试恢复，Ed25519 签名防重放，事务持久 ACK/幂等，资产/工作空间隔离，配置版本/启停/周期回执、撤销、真实样本查询。当前签名 HTTPS，不是设备证书 mTLS。

客户端本地独立状态、Windows current-user DPAPI、Linux 0700/0600、原子写、进程锁、有界队列、精确 ACK 删除。每种模板使用不同状态目录。PVE token 仅由环境传入。

## 本轮证据与复测

| 测试 | 最终结果 | 范围和证据 |
| --- | --- | --- |
| Rust 单元/本机采样测试 | 22 通过 | 配置、签名、队列恢复/ACK/限额、Docker/PVE 解析/异常/超限和真实 host sample；`.local-dev/telemetry-rust-tests.log` 已复制到本轮公开证据目录 |
| 前端 VM/fake-DOM 回归 | 155 通过 | 新增 Agent 路由/权限/晚响应/转义/空失败测试；不是浏览器全覆盖 |
| Go 全套原生 PG race | 90 测试事件通过，0 fail/skip | `evidence/2026-10-18T09-10-13-113Z-797c32/report.json`；包括 6 项新增 telemetry 测试函数 |
| 原生 PG 备份恢复 | 141 断言通过 | `evidence/full-qa-20261018/backend/2026-10-18T09-08-53-275Z-recovery-7dd017/report.json`；含 008 结构 |
| 实际二进制 HTTPS / PG 端到端 | 27 断言通过 | `evidence/2026-10-18T09-17-21-769Z-telemetry-2a2a2e/report.json`；Linux host、Windows host、Linux Docker 实际进程注册和上报，数据库独立回读 |
| 配置、断网、重启、撤销 | 上述 E2E 内通过 | 配置 v2 回执、disable 不产生新样本、停服期间入队、服务重启补传+新样本 ACK、撤销拒绝且队列不假清空 |
| Windows 原生运行 | 已实测子范围 | 三 exe version、主机 CPU/内存/4 磁盘/3 网卡、本地 DPAPI 重新打开、真实 HTTPS 注册和上报；无 SCM 自启验收 |
| Docker Engine | 已实测子范围 | WSL Engine 29.1.3，真实只读 inventory/stats；独立样本曾有 7 容器（6 running/1 stopped），测试期间容器数量会随隔离测试变动；E2E 实际上报成功 |
| 浏览器子流程 | 已实测 | 独立临时 PG/HTTP loopback 浏览器环境登录、无数据不显示 0、实际 WSL 样本、字段式下发周期、期望/应用 2/1 到 2/2。截图 `telemetry-config-applied.jpg`；生产 HTTPS 在 IAB 因 CA 信任警告未继续，未绕过警告 |

首次 E2E 21 个断言后 socket hang up 原因是测试脚本旧 shutdown 延迟闭包误杀重启进程，而非 Windows Agent 未上报；固定捕获 child 并清理 timer，重跑全部 27 断言。保留失败证据 `evidence/2026-10-18T07-15-53-104Z-telemetry-74b5f3/report.json`。

一次全套测试发现既有 CSV 测试随机 ID 以 `-` 开头时正确被公式保护，断言却未考虑此前缀；修复测试预期（不去掉生产 CSV 安全保护），全套复测 90 PASS。失败证据 `evidence/2026-10-18T07-14-57-253Z-816a9f/report.json` 保留。

修复 CPU 窗口元数据：在 CPU refresh 后立即记录窗口，不把后续磁盘枚举时间混入 CPU interval；修复三个模板共用默认状态目录的问题。最终发布二进制在最后一次 E2E 中按 SHA256 绑定。

## 未完成与部署限制

- PVE 真实 API/权限/节点与 VM/LXC 数据没有验证，保持 BLOCKED，不能以 fixture 替代。
- Windows SCM、Linux systemd 安装/停启/重启后采集未验收；提供模板/前台启动与显式安装脚本，不擅自提权或安装。
- Windows Docker named pipe 未实现；HTTPS/mTLS 可配置但未实测。PVE guest 迁移身份对账、多采集器去重未实现。
- Linux 仅 x86_64 GNU glibc >=2.34 + libgcc_s；无 ARM64/musl 包；Windows exe 未签名。
- 非完整 PRD 指标：没有进程排行/登录事件/日志、磁盘 IO/inode、逐核 CPU 分类、完整网卡身份/路由、聚合/告警链路。
- 未实现压缩上传、完整证书续期/自动签名升级、灰度发布、全局 retention/时间分区。30 天清理由该 Agent 成功摄取触发，离线/撤销历史不会定时全局清理。
- 尚无长期生产负载、故障磁盘、服务账户权限矩阵或跨版本 OS 验收。其他演示页面仍是演示，没有将所有监控需求提升为通过。

矩阵只更新受影响需求的实现/证据与未完成边界，不把任何整条需求提升为 VERIFIED。

## 发布与运行状态

WSL `release/telemetry-0.1.0/` 及 Windows 用户文档目录下同名 `release/telemetry-0.1.0/` 提供 Windows ZIP、Linux GNU tar.gz 和已解压的二进制目录。含独立 TOML 模板、前台脚本、systemd 模板、协议、依赖许可证清单及 SHA256。Windows 复制后逐项验证 870 个打包文件哈希；压缩包完整性通过，Linux host/Docker 与 Windows host 二进制哈希与最终真实 E2E 一致。

原 WSL HTTPS 服务已应用迁移 001–008 并运行，`https://127.0.0.1:18443/#agents`；用当前本地平台账号实际登录并检查新 Agent API 返回 200。开发库未写入隔离测试身份/样本，目前 Agent 数为 0，需要对实际目标注册。证据 `evidence/telemetry-20261018-final/live-service.json`。

浏览器额外验证 390px：初版表格使整个弹窗横向溢出，改成单独的可键盘聚焦横向滚动区域后复测。样本变旧显示 stale，不继续显示健康绿色。相关截图和最新 155 项前端结果在 `evidence/telemetry-20261018-final/`。临时浏览器测试库与服务已清理。
