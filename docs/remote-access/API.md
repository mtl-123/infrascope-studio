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

### 组织、导入与发现确认

管理员 `GET/POST /api/remote-access/organizations`、`PATCH /organizations/{id}`：name/description/parentId/enabled/memberIds，更新必填 version。成员是当前 workspace 平台用户，不是联系人；最多 500，空集合不通配。父组织仅分类，不自动继承授权；直接成员只读该组织绑定的资产元数据，不授予修改、人员目录或远程权限。停用父级不自动禁用子级，页面明确提示。循环、跨 workspace、版本冲突拒绝，事务保存与审计，workspace advisory lock 防并发重挂环。

`GET /organizations/options?offset=0` 为 admin/asset_manager 的最小 id/name/enabled 目录，每页 100；manager 只看到直接成员组织。前端逐页读取，不能默默只显示首 100。资产新 `organizationId` 对应 GET `organization_id`；未传保留原值，空字符串明确清除。显式分配必须同空间启用组织，manager 须为成员；未变的既有归属由前端省略，避免停用组织阻断其他字段编辑。

`POST /api/v1/asset-imports/preview`：`{csv,claimantId,organizationId?}`，asset.manage 权限。UTF-8 CSV 最多 512 KiB、200 数据行；必填列 inventoryId/name，可选 category/kind/osFamily/environment/site/business/description。不接受秘密、端点或授权列。CSV 未填分类默认 server/physical/other，这些是导入默认值，不是观测事实。预览保存任务，不创建资产；逐行 ready/invalid/duplicate，30 分钟有效，重复 inventoryId 不覆盖已有资产或负责人。

`GET /api/v1/asset-imports` 返回本人最近 100 项（admin 当前 workspace），`GET /asset-imports/{id}` 回读详情。`POST /asset-imports/{id}/confirm` 仅 `{confirm:true,rowNumbers:[1,...]}`，行号是数据行 1 基，必须明确选择；只接受 ready/failed/已创建幂等行，重新校验联系人和组织。行级 savepoint 支持部分成功；数据库故障整体回滚，不能伪装人员校验失败。相同任务行锁串行、跨任务唯一 inventoryId 防重，按稳定标识顺序插入防反序批次死锁。已经创建的不重建；payload 由服务端预览冻结，不接受确认时篡改字段。

`POST /asset-imports/{id}/cancel {confirm:true}` 取消 preview/partial 的剩余候选，已创建资产保留；confirmed 任务不允许取消删除。取消后确认 409，预览过期确认 410。确认/取消后 GET 回读；POST 成功但回读失败显示任务 ID 及已提交待核对，旧预览不可再次操作。关闭弹窗后迟到请求不重开；最终关闭详情刷新真实任务列表。

`POST /api/v1/discovery/local-preview {claimantId,organizationId?}` 只读发现 Go 平台所在 WSL Linux 的主机名、OS/内核、接口、挂载点容量摘要，生成相同待确认任务。无 host/url/command 输入、无网段扫描，不读秘密。稳定标识为 machine-id 摘要（不返回原 machine-id），事实带 observedAt、失败/截断状态。非 WSL Linux 或非 Linux 返回明确不支持，不能猜物理/虚拟分类。确认仍不生成端点、账号或授权，不安装 Agent。

来源保存 `ra_asset_origins`，资产 GET 的 origin 返回 kind/jobId/observedAt/facts。CSV 来源为手工导入；local_discovery 为一次本机观测，不冒充 Rust Agent 或持续遥测。观察时间来自实际 facts，非入库等待完成时。管理员代确认记录实际管理员为资产创建者/审计主体，任务创建者保留，不冒充原操作者。

### 统一资产与只读范围

`GET/POST /api/v1/assets`、`GET/PATCH /api/v1/assets/{id}` 与原 `/api/remote-access/assets` 使用同一处理器、权限、稳定 ID 和版本，无 demo 导入。主导航“设备与使用人”与远程“资产与账号”读取同一数据。“组织与人员”读取真实手工目录；企业微信同步仍未实现。

列表支持 `q,category,environment,site,business,ownerId,groupId,ids,offset`。ownerId 匹配使用人或待认领人，groupId 指资产可见范围组而非旧文本分组；ids 逗号分隔最多 100 个。先授权再筛选分页，每页 100。详情忽略有效的分页 offset，不因翻页丢失已知单资产。新增 `canManage` 仅为 admin 或原创建者 asset_manager；客户端隐藏按钮不能代替服务端授权。

可见范围：管理员当前 workspace；资产管理员本人创建资产；包含 asset.view 的有效远程授权且账号启用未归档；或有效只读资产组范围。审计员显式有 asset.view 操作点，但同样需要范围，远程 policy 继续拒绝连接。责任联系人不是授权主体。

`GET /api/v1/assets/export` 使用同一权限与筛选，不仅导出当前页，不接受 offset 静默截断。最多 1000 条，超过整体拒绝 `422 export_limit`。CSV 包含 id/name/category/kind/os_family/environment/site/business/enabled/archived，所有字段中和公式前缀（含前导 Unicode 空白和控制字符）；无邮箱/凭据，记录 asset.export 审计。导出到达浏览器后不可能撤回已下载数据。

管理员专用 `GET/POST /api/remote-access/asset-groups`、`PATCH /asset-groups/{id}`：字段 name/description/enabled/startsAt/expiresAt/assetIds/userIds/groupIds，PATCH 必填 version。POST 不授予全 workspace；空数组为空范围。分别限制 500 资产、100 用户、100 用户组，引用必须同 workspace；组列表每页 100，offset。startsAt/expiresAt 为明确 RFC3339 时间，未来/过期可保存但不生效；冲突 409，不部分替换引用。名称 workspace 内唯一。

资产组仅授予资产元数据读取，不授予编辑、人员目录、账号查看/使用、SSH/SFTP/RDP 或秘密。停用/过期/移除用户组成员在下一请求立即生效；其他独立有效授权不受该范围组撤销影响。资产停用/归档撤销远程授权，但只读资产组仍可读取登记元数据，不能将其当设备在线。所有范围变更事务内审计。

前端退出、改密成功、身份 401 会失效旧异步请求并清理身份缓存；退出失败明确“注销未确认”，重新读服务端会话，不假装成功。编辑资产组时，未修改的原时间保持服务端精度，不因字段表单截断秒/微秒而提前授权。

### P2 手工人员与责任

`GET /people?q=&offset=0&ids=id1,id2`：限 admin/asset_manager，当前 workspace，姓名/部门搜索，100 条/页，ids 最多 20 用于恢复已选引用。返回 `id,display_name,department,email,contact_type,source,enabled,version,email_configured`；只有管理员可读取邮箱，资产管理员得到空 email 和是否配置标记。operator/auditor 不能读取目录。邮箱不参与搜索，也不出现在资产或责任历史响应中。

`POST /people`、`PATCH /people/{id}`：限 admin（user.manage）。字段 `displayName,department,email,contactType=internal|external,enabled`；PATCH 必带当前 `version`，冲突 409。姓名 180、部门 240、邮箱 254 UTF-8 字节上限。邮箱可空，非空必须单一地址；不验证收件或发送消息。source 只能由服务端产生为 manual，未知字段、伪造企业微信来源被拒绝。联系人没有登录能力、没有隐式授权；同名人员有独立 ID，停用不删除历史引用。

资产请求增加 `category=server|nas|pve|switch|printer|scanner|other`、`environment/site/business`（各最多 120 UTF-8 字节）以及 `ownership`。category 与 kind/OS 独立，旧客户端新建未传 category 时兼容为 server；当前字段式表单要求主动选择类别。远程 endpoints 可以为空，表示仅登记、未配置远程通道，不代表在线、离线或已有采集。

```json
{"ownership":{"state":"pending","userId":"","claimantId":"person-id","operationsId":"","businessId":"","notificationIds":[],"backupIds":[]}}
```

assigned 必须 userId 且 claimantId 为空；pending 必须 claimantId 且 userId 为空。所有 ID 指向当前 workspace 的人员，而不是 ra_users。每个通知/备用列表最多 20 人且不可重复；不同职责可同人。显式分配验证全部引用存在且启用，持锁到事务提交。资产、引用及责任快照同事务更新，复合外键拒绝跨 workspace。

新建必须传 ownership；迁移旧资产 `ownershipLegacy=true`，首次编辑须补齐责任，用户不能传该字段绕过规则。非 legacy PATCH 省略 ownership 保留原值；明确提交则重新校验人员，即使有停用旧人员也不能冒充新绑定。前端责任内容完全不变时省略 ownership，警示旧停用引用但允许修改其他字段或归档。分类/环境/地点/业务字段省略时保留现值。既有 PATCH 其他字段仍为完整编辑语义。

`GET /assets/{id}/ownership-history`：限该资产管理范围，返回最近最多 100 条，含 `revision,ownership,people_snapshot,changed_by,changed_at`。责任实质变化才追加；snapshot 保存当时姓名/部门/联系人类型，不保存邮箱，后续改名不篡改历史。责任不授予远程权限。资产保存继续沿用原版本失效与会话终止行为。

移除所有远程端点会清除对应 host key，但保留账号、密文凭据和授权记录。缺端点时真实操作返回 `404 endpoint_unavailable`，不生成 SSH/SFTP/RDP 任务；重新配置 SSH/SFTP 后必须重新确认指纹。归档撤销的授权不会因取消归档而自动恢复。

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

资产 PATCH 额外必填从最近一次 GET 取得的整数 `version`。省略或小于 1 返回 400 `asset_version_required`；版本已改变返回 409 `asset_version_conflict`，不覆盖已保存资产、端点或主机信任。成功保存递增版本；发生冲突应重新读取并核对差异，禁止静默自动重试覆盖。POST 创建资产不要求版本。此为 2026-10-18 的兼容变更，旧调用方需补传版本；现有编辑器已同步。

Limits：`readRoots,writeRoots,maxFileBytes,maxTotalBytes,maxFiles,maxDepth,maxConcurrent,allowOverwrite,allowInteractive`。目录必须是规范绝对 SFTP 路径，空根集合不表示“所有目录”；主体、账号和资产必须同 workspace。授予者不是 admin 时，不能超过自己可委派的有效期、动作或范围。批量分配由页面逐条提交并报告已完成数量，非全有或全无事务；每条授权单独审计。

列表返回 snake_case 数据库字段（UI 已作对应）；创建返回 `{id}`。资产接口接受 q（名称、类型、系统、分组、标签）和 offset（默认 0），每页最多 100 项，先执行 workspace/授权过滤再搜索分页；管理页和分配向导均支持翻页与服务端搜索。授权列表最多 2000、会话历史 200、审计最新 500。大规模完整历史检索/导出不应把这些上限当无分页全量接口。

## SSH / LinuxTab

### 按服务器连接准备与本人授权

`GET /api/v1/assets/{id}/remote-readiness`：当前可见资产的只读预检，返回 assetId/name、canManage、canGrantSelf、三协议端点/账号/状态/原因及connectorReady。普通只读用户不因此看到未授权账号信息。状态含缺端点、账号、凭据、授权、主机指纹、网关策略、连接器或 ready_to_attempt；后者不是认证成功。不拨号、DNS、解密或修改任何目标，实际连接入口重新授权。

`POST /api/remote-access/accounts/{id}/grant-self`：仅 admin、近期重新认证与CSRF，`confirm:true`、明确 protocols、expiresAt（30天内）、idempotencyKey、readRoots/writeRoots、allowFileWrite/allowClipboard/allowDrives/allowInteractive。SFTP必须显式readRoots，写入默认关闭；不自动覆盖、不授临时凭据。同键相同请求只返回原grant，不重复创建、不恢复撤销；同键不同意图409。凭据与主机信任不由该接口写入。权限记录与审计同事务，当前用户由服务端会话决定，客户端不能指定其他userId。

Windows连接器能力必须显式报告基础自检及签名配置成功，当前用户/浏览器绑定、未撤销、心跳新鲜并在HTTPS平台才认为可发起。RDP前端仍须手动选择设备，真实mstsc认证结果不在该预检证明范围。

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
