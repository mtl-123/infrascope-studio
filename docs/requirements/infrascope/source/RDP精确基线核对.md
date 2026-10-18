# RDP 精确基线快速核对

本表只是便利入口，原附件全文仍为规范。每项必须核对实际行为，不只检查字符串存在。

## 必须保留的十八项设置

1. full address:s:<IPv4/host:port 或 [IPv6]:port>
2. username:s:<用户名>
3. prompt for credentials:i:<同时提供用户名密码时0，否则1>
4. authentication level:i:2
5. enablecredsspsupport:i:1
6. negotiate security layer:i:1
7. redirectclipboard:i:<开1关0>
8. redirectdrives:i:<开1关0>
9. drivestoredirect:s:<全部*、指定规范盘符、关闭为空>
10. screen mode id:i:<全屏2否则1>
11. use multimon:i:<开1关0>
12. smart sizing:i:1
13. dynamic resolution:i:1
14. networkautodetect:i:1
15. bandwidthautodetect:i:1
16. connection type:i:7
17. compression:i:1
18. bitmapcachepersistenable:i:1

## 本机兼容页 DOM 标识

~~~text
statusDot headerStatus pageTitle rdpTargetSummary
connectorIndicator launcherState setupSigningButton
rdpForm targetHeading rdpAddress rdpPort rdpUsername rdpPassword showPassword
resourceHeading redirectClipboard redirectDrives fullscreen multiMonitor
driveControls driveMode driveListField driveList
rdpValidation launchMstscButton toast
~~~

共 26 个。平台集成布局可遵守宿主组件体系；保留独立原型兼容页时保留对应 ID 与行为。

## 四个本机 API

- GET /api/local-token
- GET /api/rdp/signing-status
- POST /api/rdp/setup-signing
- POST /api/rdp/connect

受控模式不得让旧自由连接接口绕过平台授权。具体请求、响应头、错误、超时、字段长度和非 Windows 行为依原附件及批准的兼容改进逐条核对。

## 不可混淆

- SHA-256 策略指纹与用于查找证书私钥的指纹不是一个参数，工具支持需实机确认。
- 凭据目标 TERMSRV/host 不含端口；不同端口仍可能冲突。
- 30 秒清理不证明已消费凭据，也不代表 mstsc 或远端会话退出。
- 签名可信发布者不等于远端服务器 TLS 身份可信，不能关闭身份验证来消除提示。
- 明文密码不写 .rdp、不走 argv、不持久化到浏览器；不承诺本机管理员无法提取内存。
