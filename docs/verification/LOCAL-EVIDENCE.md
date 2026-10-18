# 本机历史验收资料边界

原始浏览器截图、运行日志、主机信息、临时测试环境记录保留在原开发机的 `docs/implementation/evidence/`，不提交到公开仓库。它们可能包含本地环境信息，不属于构建服务所需源码。

工作矩阵 `docs/requirements/infrascope/05_需求追踪矩阵.csv` 的 `local_evidence_paths` 保留原记录位置。公开仓库的 `evidence_paths` 指向本说明，表示证据存档边界，不表示本说明本身验证了对应需求。

187 条 MUST 保留全部原实现与验收状态，目前没有整条需求被标记为 VERIFIED/PASS。本次整理不会把“代码已实现”改成“产品已验收”。需要外部设备或原始证据的复核项，应在原开发环境执行或取得经人工审阅的资料。

构建与测试以仓库脚本和 GitHub Actions 为准。当前代码结构、版本、复核命令见 `docs/development/BUILD-AND-RUN.md` 和 `.github/workflows/ci.yml`；整理验证摘要见 `REPOSITORY-EXPORT-2026-10-18.md`。
