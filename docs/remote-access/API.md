# 远程接入 API 与消息协议

前缀 `/api/remote-access`。用户接口使用安全会话 Cookie；非 GET/HEAD 额外要求公开 Origin 完全匹配以及 `X-CSRF-Token`。JSON 严格拒绝未知字段、错误类型、多个对象，最大 1 MiB。示例中所有 ID 都必须来自当前用户获准读取的 API，不能从演示 localStorage 获取。

错误结构 `{code,error,gatewayId?}`。401 未登录/凭据认证失败；403 禁止；404 不存在或不暴露他人对象；409 冲突；410 已过期/已消费；413 超限；429 限流；502 远端失败；503 网关/模块/密钥不可用。JSON 响应 no-store；不会向浏览器返回 SQL 错误或远程秘密。

## 身份与管理

| 方法 / 路径 | 请求字段 | 返回 / 权限 |
| --- | --- | --- |
| POST `/auth/login` | username,password | id,displayName,role,mustChangePassword,csrf；登录限速 |
| GET `/auth/me` | 无 | 当前主体、permissions、csrf、gatewayId |
| POST `/auth/logout` | `{}` | 撤销当前登录及其受控连接 |
| POST `/auth/reauth` | password | 5 分钟敏感操作窗口 |
| POST `/auth/password` | currentPassword,newPassword | 撤销全部登录，要求重新登录 |
| GET/POST `/users` | 新建 username,displayName,role,initialPassword | user.manage，写操作重新认证；新用户强制改密 |
| PATCH `/users/{id}` | role?,enabled?,initialPassword? | 禁用/角色变化/重置使旧登录失效；禁止自己降级锁死 |
| GET/POST `/groups`，PATCH `/groups/{id}` | name,members（用户 ID 数组） | group.manage；成员必须同 workspace |
| GET `/grant-subjects` | 无 | grant.manage；最小用户/组目录，不含秘密 |

平台角色是 admin、asset_manager、operator、auditor。公开注册未开放。首个管理员仅通过 CLI stdin 初始化。

## 资产、账号与授权

| 方法 / 路径 | 请求 / 返回 | 权限 |
| --- | --- | --- |
| GET/POST `/assets`；GET/PATCH `/assets/{id}` | name,kind=physical/virtual,osFamily=linux/windows/other,groupName,tags,description,metadata,enabled,archived,inventoryId,endpoints | 读取按主体范围；写 asset.manage，资产管理员限自己管理资产 |
| POST `/assets/{id}/test` | protocol | TCP reachability 与 RDP 用户端验证不同，不推断认证成功 |
| POST `/assets/{id}/host-key/probe` | protocol=ssh/sftp | 资产管理员读取未受信任指纹，不认证登录 |
| POST `/assets/{id}/host-key/approve` | protocol,fingerprint,algorithm,confirm=true | 最近重新认证；替换该算法的批准指纹并审计 |
| GET/POST `/assets/{asset}/accounts`；GET/PATCH `/accounts/{id}` | name,username,authType=password/private_key/interactive,protocols,enabled,archived | 非秘密元数据；authType 创建后不可静默更换 |
| POST `/accounts/{id}/credential` | action=set/clear,secret={password?,privateKey?,passphrase?} | 资产范围管理 + 最近认证；版本递增；无明文回显 |
| POST `/accounts/{id}/test` | protocol=ssh/sftp | 真认证；SFTP 单独验证子系统 |
| GET/POST `/grants`；PATCH/DELETE `/grants/{id}` | userId 或 groupId（二选一）,assetId,accountId,actions,protocols,limits,startsAt,expiresAt | grant.manage + 可委派范围；DELETE 为撤销，不抹去历史 |
| GET `/my/access` | 无 | 仅当前有效、启用账号与授权信息 |

Endpoint：`{protocol,host,port,gatewayId}`；端口 1–65535。协议独立。metadata 只接受 provider/vmName/instanceId/hypervisorLabel。资产和账号归档通过 PATCH 的 archived 实现。

Limits：`readRoots,writeRoots,maxFileBytes,maxTotalBytes,maxFiles,maxDepth,maxConcurrent,allowOverwrite,allowInteractive`。目录必须是规范绝对 SFTP 路径，空根集合不表示“所有目录”；主体、账号和资产必须同 workspace。授予者不是 admin 时，不能超过自己可委派的有效期、动作或范围。批量分配由页面逐条提交并报告已完成数量，非全有或全无事务；每条授权单独审计。

列表返回 snake_case 数据库字段（UI 已作对应）；创建返回 `{id}`。资产接口接受 q（名称、类型、系统、分组、标签）和 offset（默认 0），每页最多 100 项，先执行 workspace/授权过滤再搜索分页；管理页和分配向导均支持翻页与服务端搜索。授权列表最多 2000、会话历史 200、审计最新 500。大规模完整历史检索/导出不应把这些上限当无分页全量接口。

## SSH / LinuxTab

- POST `/ssh/sessions`：`{assetId,accountId,cols,rows,temporaryCredential?}`。cols 10–500、rows 2–300；返回真实 ready 会话 `{id,state,gatewayId}`，失败返回具体 code。temporaryCredential 仅在全局开关和精确授权、重新认证同时满足时接受；目标/用户名不能覆盖。
- GET `/ssh/sessions`：本人历史；GET `/ssh/sessions/{id}`：当前状态、sequence、windowId、gatewayId、accountId、assetId；DELETE：结束本人会话，需 ssh.close。
- GET `/admin/sessions`：session.viewAll；DELETE `/admin/sessions/{id}`：session.terminate，元信息范围限当前 workspace。
- POST `/ssh/sessions/{id}/attach-authorizations`：`{windowId}`，返回短期 authorization。30 秒、一次使用、与平台登录/用户/窗口/SSH 会话绑定。
- WSS `/ssh/sessions/{id}/stream`：携带 Cookie/Origin，首条消息 `{type:"attach",authorization,lastSequence}`，令牌不放 URL。

服务端：`status {state,lease,reason?}`、`output {sequence,data}`（data 为原始 SSH 字节 base64）、`error {code,message}`。

客户端：`input {lease,sequence,data}`（data 是 PTY UTF-8 输入，单条 32 KiB），`resize {lease,cols,rows}`，`ack {lease,sequence}`，`heartbeat {lease}`，`close {lease}`。控制租约递增；接管关闭旧 socket；输入序号严格递增，不重放未确认命令。重附着只回放服务端仍保留的输出，缺口明确报 replay_gap。缓冲上限 1 MiB，慢客户端触顶结束会话并给出原因，不无限缓存。

浏览器只将输出写入 xterm，屏蔽 OSC52/自动剪贴板和 OSC8 链接。多行粘贴先预览，使用 xterm bracketed paste。新窗口 URL 只带非秘密 sessionId，依靠同源 Cookie、所有权校验、一次附着授权与控制租约；回看快照只通过已登记子窗口的同源 postMessage 内存传递。

默认短断保留 60 秒、空闲 1800 秒、最长 28800 秒。撤销轮询默认 5 秒、单次 DB 检查 3 秒；正常健康数据库下通常一个周期内生效，DB/网关故障会失败关闭。高并发整体上限需实际负载验证，不能把该周期描述成无条件实时 SLA。

## SFTP 和任务

| 方法 / 路径 | 契约 |
| --- | --- |
| GET `/sftp/entries?accountId=&path=&offset=` | 返回规范 path、entries(name,directory,symlink,size,modified,mode)、total、nextOffset、读写根；每页 200 |
| POST `/sftp/directories` | accountId,path；需要 sftp.mkdir |
| POST `/sftp/rename` | accountId,path,destination；目标已有同名时冲突 |
| POST `/sftp/delete` | accountId,path,recursive,confirm；禁止删授权根 |
| POST `/transfers` | accountId,direction=upload/download,target,conflict=ask/skip/rename/overwrite,confirmOverwrite,paths；download paths 为目标目录内的相对路径 |
| GET `/transfers` | 本人显示列表；跨网关元信息持久化 |
| GET `/transfers/{id}` | 本人任务与条目、确认字节、状态、重试和错误；会重新检查有效授权 |
| POST `/transfers/{id}/items` | `{items:[{path,directory,size,modifiedMs,sha256}],final}`，每批至多 500 |
| PUT `/transfers/{id}/items/{item}/content` | 二进制 body ≤4 MiB；Upload-Offset、Upload-SHA256；目录用空 body；返回确认 offset |
| POST `/transfers/{id}/commit` | `{}`，重新鉴权、校验块、同名策略、原子提交，返回 state 和 failedItems |
| POST `/transfers/{id}/control` | action=pause/retry/cancel_item；retry 带 conflict,confirm；cancel_item 带 itemId |
| POST `/transfers/{id}/cancel` | 停止并标记整个任务；尽力清理属于本任务的临时对象 |
| POST `/transfers/{id}/hide` | 清除本人已结束任务的显示记录，保留审计和远端文件 |
| GET `/transfers/{id}/content` | 目录/多文件为流式 ZIP；`?format=file` 仅对单文件生效 |

上传幂等按 item + offset + size + SHA256 校验；同 offset 不同内容拒绝。正在传输的文件任务绑定原目标，不随活动终端变化。上传完成字节不等于已提交。实时 ZIP 不提供暂停/续传，浏览器按 taskId 读取最终状态。下载 URI 没有 bearer token，仅靠当前用户 Cookie/授权。

网关只保留有界块和有数量上限的清单；目录 ReadDir 在分页之前读取目录项元数据，因此超大单目录的元数据内存仍需容量测试。大文件内容本身流式。任务明细返回已确认 chunks 的 offset/size/sha256；页面恢复上传前逐块核对本地已确认前缀，服务端独立校验远端前缀。上传文件 mtime 用于恢复身份校验，不承诺还原全部 POSIX 权限或时间戳。

## Windows 设备协议

用户 POST `/connectors/pairing-challenges` → `{challenge,expiresIn:120,platform}`。本机 POST `/connector/pair` 字段为 challenge、PKIX PEM publicKey、name、Windows SID SHA256、version、signature、origin。证明消息 `pair\nchallenge\norigin\nwindowsUserHash`，Ed25519 签名。配对返回 connectorId/browserBindingId，只有设备收到密钥关系，私钥不离开本机。

签名设备接口统一 POST `/connector/{poll|redeem|event}`，请求头 `X-Connector-Id/Time/Nonce/Signature`。时间为 Unix 秒，窗口 ±30 秒；签名原文为 `METHOD\nescapedPath\ntime\nnonce\nsha256(body)`。nonce 原子插入去重；不能通过重放再次兑换。

- poll：capabilities,windowsUserHash → 仅该设备的未消费任务、非秘密目标和显示参数。
- redeem：launchId,locallyConfirmed=true → 在事务锁与再次授权后仅向此设备返回 address,port,username,password,options,permittedActions,interactiveAllowed,expiresAt；一次消费。
- event：launchId,state,pid?,code? → received/signing_setup_required/started/failed/cleanup_completed/cleanup_failed 的实际反馈。PID 是本机进程标识，不是远程 Windows 登录证明。
- 用户 GET `/my/connectors`，POST `/connectors/{id}/revoke`：归属和重新认证控制，撤销未兑换任务。
- 用户 POST `/rdp/launches`：assetId,accountId,connectorId,browserBindingId,idempotencyKey,options。options 包含 redirectClipboard,redirectDrives,fullscreen,multiMonitor,driveMode,driveList；服务端拒绝越权 true。
- GET `/rdp/launches`、`/{id}`：本人状态元信息。票据实质为随机任务 ID + 设备签名认证 + 一次原子消费，不是可在浏览器转送密码的 bearer URL。

## 审计与健康

GET `/audit-events` 需 audit.read，默认只返回元数据，绝不返回键盘输入/终端输出/文件内容。GET `/health` 需管理或审计权限，当前返回 SSH/SFTP 数量、文件任务和确认字节、清理待办、连接器在线/版本、会话结束原因、堆内存、goroutine、带宽上限和撤销轮询配置。它不是完整 Prometheus 指标集，生产告警与容量仍需现场验收。
