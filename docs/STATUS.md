# 当前实现与验收边界

代码包含真实的统一资产/人员/组织、导入确认、权限/凭据、SSH/SFTP 控制面、Windows 连接器、Rust host/Docker/PVE 客户端、签名上报及真实样本查询、Linux 接入引导与手册。

原有监控、网络、日志、告警、通知、SRE/AIOps 页面仍有演示内容。不能因源码可构建、自动测试通过或收到单个样本就宣称完整产品验收通过。

- 全部 187 条 MUST 保留；当前矩阵没有任何整条需求标为 VERIFIED/PASS。
- 真实 PVE、Windows Docker HTTPS、Windows SCM/Linux systemd 重启、用户目标 SSH/SFTP/RDP 及生产容量需各自环境验证。
- 精确手机断点曾因浏览器 viewport 工具未生效而未签通过。
- 历史实施报告在 docs/implementation/，按日期阅读，后续采集客户端增量优先于更早的“未实现 Agent”记录。
- 当前源码构建与运行说明以根 README 和 docs/development/BUILD-AND-RUN.md 为准；历史的本机绝对路径不是依赖。

此次整理提供可从干净 checkout 构建服务的入口和持续集成，不更改需求验收分母或擅自提升状态。
