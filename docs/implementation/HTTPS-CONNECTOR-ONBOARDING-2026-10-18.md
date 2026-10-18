# HTTPS、本机连接器与单表服务器接入

2026-10-18，Asia/Shanghai。用户授权将 HTTPS 与 Windows 本机连接器配起来，目标凭据由用户填写，必要 UAC 再请求。当前控制面已实配，但没有目标主机登录证据，整项远程验收仍未完成。

## 已实际运行

- WSL Go 原生 TLS 1.2+：`https://127.0.0.1:18443`，旧 `http://127.0.0.1:18080` GET/HEAD 固定307跳转，API写请求不在HTTP重放。HTTPS Cookie为Secure，不再因LoopbackTest降低。
- 生成30天 localhost/127.0.0.1/::1自签serverAuth叶证书（CA:FALSE），私钥仅WSL `.local-dev/tls/server.key`，0600。仅将该公钥证书加入当前Windows用户Root，未安装系统范围CA、未修改防火墙。Windows标准证书验证HTTP200，未使用skip verify。
- 当前Chrome实际验证HTTPS正常；Codex内嵌浏览器报证书不信任，未绕过浏览器安全提示，用户入口改用Windows Chrome。不要把内嵌浏览器失败标为通过。
- Windows Node受控连接器已复制明确源文件至当前用户LocalAppData私有运行目录并隐藏启动，绑定127.0.0.1:4173。出站仅批准HTTPS，NODE_EXTRA_CA_CERTS仅信任该公共证书，未关闭TLS验证。
- 从实际Chrome登录会话生成配对挑战，在本人Windows连接器提交，平台显示有效绑定与心跳；DPAPI身份重启后保留。不是另一个脚本登录会话假配对。
- Windows mstsc/rdpsign/Credential API只读自检和既有签名配置成功。现有签名证书至2029-08-29有效，本轮没有运行Install，没有新UAC或更改RDP签名策略。

## 连续服务器表单

设备与使用人新增“添加服务器并连接”：一次填写名称、Linux/Windows、literal IP、独立端口、系统账号、密码/私钥或RDP交互模式、明确责任人、SFTP目录、期限和资源开关。

`POST /api/v1/servers/onboard` 仅管理员+近期再认证+CSRF+明确确认，在一个事务中创建资产/端点、加密秘密、本人限期grant、精确资产/IP/协议/端口许可和审计。失败全回滚；幂等请求用主密钥HMAC防密码摘要离线猜测。响应不含秘密，不自动创建目标OS用户、不改防火墙、不自动信任SSH host key。

精确许可只供中央SSH/SFTP出站；不开放整个CIDR。端点改动/删除撤销该许可，改回不自动恢复；保留禁止特殊/网关自身地址规则。RDP数据从本人Windows到目标，不宣称中央许可能替代本机网络条件。

成功后直接进入该资产的连接面板，SSH首次仍需独立核实指纹，SFTP限明确目录，RDP需选本人已绑定设备并在本机确认。IP和凭据尚未由用户填写，未真实拨号任何用户目标。

## 实际失败与修复

- Windows连接器浏览器顶层导航被安全检查403：允许严格loopback+Host、无Origin、GET/HEAD根页面的document navigation；所有API保持来源和token检查。WSL真实HTTP反例确认跨站token/status仍403，Chrome页面恢复正常。
- 真Windows启动空租约恢复报SeSecurityPrivilege：原Set-Acl写入多余安全描述符部分。改为只写DACL，保留owner/group；专属临时目录/文件实机测试通过。确认租约为空后Recover返回0恢复/0失败，不碰已有凭据、不启动mstsc。
- 新表单2项身份竞态由19项VM测试真实发现并修复：重新认证期间logout、保存后列表刷新期间换身份均不得继续旧动作。失败摘要和复测在evidence保存。
- 文案回归曾缺CIDR说明导致旧测试失败，恢复准确的“精确许可不放开整个CIDR”文案后复测，不删除断言。

## 证据

- `evidence/https-onboarding-final-checks.json`：最终前端114项（19+27+28+27+13）、既有6组、连接器5项、门禁、构建/静态检查。
- `evidence/2026-10-18T05-57-11-218Z-1c7c78/report.json`：原生PG及TLS实际传输共80个测试事件含子用例，0skip。错误信任根与TLS1.1拒绝，精确端点修改失效、事务、幂等与秘密不回显验证。
- `evidence/windows-connector-live-pairing.json`：真实Windows本人设备、批准HTTPS、交互会话与自检/签名状态，无token/私钥。
- `evidence/windows-acl-live-test.txt`：Windows PowerShell5.1 DACL测试实际通过。
- `evidence/https-server-onboarding.png`：真实HTTPS填写界面，无用户凭据。

## 未完成与用户下一步

尚未真实执行目标SSH终端、SFTP上传下载、RDP认证/桌面/重定向；不能因配对或签名就绪标完成。请用户在已打开Chrome的HTTPS表单填写授权测试目标IP/端口/系统账号凭据并确认。秘密不发送聊天。只有该实际链路成功并留证后，才更新对应实机子项。

Chrome会话退出后设备仍存在，但新登录需按现有安全设计重新绑定当前浏览器会话。连接器页面有本机任务二次确认，不自动启动远程桌面。当前服务与连接器均保持运行等待用户填写。
