# 仓库整理与干净构建验证（2026-10-18）

## 分类结果

前端源码统一为 `web/`，构建输出为忽略的 `dist/`；Go 服务在 `remote-access/`，Rust 三类采集器在 `telemetry-agent/`，Windows 本机连接器在 `windows-connector/`。需求统一为 `docs/requirements/infrascope/`，使用手册、构建手册和状态边界分目录管理。完整文件导航见根 README。

`.runtime/`、`.local-dev/`、数据库、密钥、真实凭据、截图日志、依赖缓存与编译产物不进入公开仓库。旧 Sites 项目绑定也不再进入当前源码索引。原始资料留在原机，没有删除业务数据库或原主密钥。

## 验证

从待提交 Git tree 导出新目录，没有复制 node_modules、dist、build、.runtime 或 .dev-tools：

- npm ci 从锁文件安装 13 个依赖成功。
- npm run build 重新生成前端和 Go 服务包成功；Go 服务强制 CGO_ENABLED=0，不依赖原机 C 编译器。
- npm test：前端/引导 169 项、连接器 11 项、原 6 组脚本、Python 4 项、187 需求结构和源码边界检查通过。
- npm run test:service-smoke：干净副本产生的真实服务包与独立原生 PostgreSQL、全新随机管理员/密钥/证书实际启动；验证 TLS、登录、身份、健康、资产、Agent 和前端资源。测试数据库结束清理。
- npm run test:native-pg：Go race 原生数据库 90 个通过事件、0 fail、0 skip，隔离容器清理成功。
- Rust 22 项单元/采样测试通过；Linux 单平台发布打包通过，不要求为构建 Linux 包先准备 Windows 交叉工具链。
- 在干净副本执行 setup，两次执行后保留已有配置；Compose 配置校验通过。
- 当前源码与 8 个原有提交的高置信度 token/key 检查未发现目标模式；这是发布前检查，不是完整安全审计。

本机 Docker Hub HTTPS 请求超时，随后由 GitHub Actions 的 compose job 实际完成多阶段镜像构建、setup/up 和 HTTPS 登录/接口检查，结果通过。首次云端 service job 发现原生 PG 测试假设已有本地镜像缓存，现已修复为缺失时拉取固定 digest；不拉取浮动标签、不跳过测试。云端记录：https://github.com/mtl-123/infrascope-studio/actions/runs/39132759945 。

结构化结果：`REPOSITORY-EXPORT-2026-10-18.json`。完整原始日志与截图不上传公开仓库。

## 状态未提升

需求全部保留，分母 187；73 IN_PROGRESS、38 UNASSESSED、76 NOT_STARTED；180 NOT_RUN、7 BLOCKED，0 VERIFIED/PASS。历史证据路径移入 local_evidence_paths，本次整理不代替产品、外部目标或生产验收。
