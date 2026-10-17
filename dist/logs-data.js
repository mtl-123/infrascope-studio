/* Deterministic demonstration fixtures. These are not observations from connected systems. */
(function(){
  'use strict';
  const anchor=Date.parse('2026-10-18T02:10:00+08:00');
  function seed(db){
    const office=db.containers.find(c=>c.id==='c1'),billing=db.containers.find(c=>c.id==='c3');
    const make=(id,name,type,host,extra={})=>({id,name,type,host,enabled:true,state:'healthy',heartbeat:anchor,captureStart:anchor-7200000,watermark:anchor-2000,gap:false,backlog:0,ackMs:380,retries:0,rejected:0,parseErrors:0,generation:'demo-epoch-1',...extra});
    const sources=[
      make('ls-system','Linux 系统与 SSH','journald','s1',{locator:'systemd journal · ssh.service / kernel',parser:'text',checkpoint:'journal cursor',scope:'系统 / 登录'}),
      make('ls-windows','Windows 安全审计','Windows Event Log','s2',{locator:'Security · 4624 / 4625 / 4672 / 1102',parser:'native',checkpoint:'channel + bookmark + generation',scope:'身份 / 登录'}),
      make('ls-office','office-api 应用日志','Docker API','s1',{locator:'stdout + stderr · Docker 名称组',parser:'json',checkpoint:'实例 ID + stream + 接入序号',group:office?.monitorGroupId,scope:'业务 / 应用'}),
      make('ls-billing','billing-worker 应用日志','Docker API','s4',{locator:'stdout + stderr · Docker 名称组',parser:'json',checkpoint:'实例 ID + stream + 接入序号',group:billing?.monitorGroupId,scope:'业务 / 应用',state:'gap',gap:true,retries:4,backlog:128,gapNote:'02:02–02:03 发生重启，远端驱动缓存不可回读；128 条为队列待传，不是已知丢失数。'}),
      make('ls-nginx','门户访问与错误日志','文件','s1',{locator:'/var/log/nginx/access.log · error.log',parser:'text',checkpoint:'file identity + generation + byte offset',scope:'入口 / HTTP'}),
      make('ls-pg','PostgreSQL 慢查询','文件','s3',{locator:'/var/log/postgresql/*.log',parser:'text',checkpoint:'file identity + generation + byte offset',scope:'数据库',parseErrors:2}),
      make('ls-switch','核心交换机事件','Syslog TLS','w1',{locator:'collector-a:6514/TCP · TLS（配置示例）',parser:'native',checkpoint:'接入序号；设备侧产生总量未知',scope:'网络设备'}),
      make('ls-nas','NAS 审计与存储事件','NAS API','s6',{locator:'厂商审计 API · 只读凭据引用',parser:'json',checkpoint:'vendor cursor',scope:'存储',state:'delayed',watermark:anchor-47000,backlog:24,ackMs:2450}),
      make('ls-pve','PVE 任务与权限日志','PVE API','s5',{locator:'只读任务 / 集群事件 API',parser:'json',checkpoint:'任务标识 + 分页游标',scope:'虚拟化'}),
      make('ls-printer','财务打印机事件','能力待确认','s7',{locator:'等待核实厂商 Syslog / 审计 API',parser:'native',checkpoint:'未建立',scope:'外设',state:'unsupported',heartbeat:null,watermark:null})
    ].filter(s=>[...db.servers,...db.switches].some(x=>x.id===s.host));
    const rows=[],seq={};
    function add(source,ago,level,message,extra={}){
      if(!sources.some(s=>s.id===source))return;
      const src=sources.find(s=>s.id===source),host=extra.host||src.host,stream=extra.stream||host,sequence=(seq[source+'|'+stream]||0)+1;seq[source+'|'+stream]=sequence;
      const eventAt=anchor-ago*1000,observedAt=eventAt+(src.id==='ls-nas'?45000:700+(sequence%7)*180),id=[source,stream,'demo-epoch-1',sequence].join(':');
      rows.push({id,source,host,stream,generation:'demo-epoch-1',sequence,eventAt,observedAt,level,message,service:'',group:src.group||'',instance:'',traceId:'',patternKey:'',actor:'',outcome:'',fields:{},...extra});
    }
    for(let i=0;i<20;i++)add('ls-system',3500-i*170,'INFO',`systemd: scheduled task completed pid=${2000+i}`,{patternKey:'scheduled_task'});
    add('ls-system',220,'INFO','sshd: Accepted publickey for ops from 192.0.2.24 port 51220',{actor:'ops',outcome:'success',loginType:'SSH 公钥',sourceIP:'192.0.2.24',eventCode:'ssh_accepted',patternKey:'ssh_accepted'});
    add('ls-system',190,'WARN','sudo: ops executed systemctl reload nginx',{actor:'ops',outcome:'privilege',loginType:'sudo',sourceIP:'192.0.2.24',eventCode:'sudo',patternKey:'sudo'});
    for(let i=0;i<18;i++)add('ls-windows',3300-i*160,'INFO','An account was successfully logged on',{actor:i%2?'svc-backup':'ops-admin',outcome:'success',loginType:i%2?'3 · 网络登录':'10 · 远程交互',sourceIP:'192.0.2.41',eventCode:'4624',patternKey:'windows_login_success',fields:{channel:'Security',record_id:84000+i}});
    for(let i=0;i<12;i++)add('ls-windows',260-i*17,'WARN','An account failed to log on: unknown user or bad password',{actor:'svc-backup',outcome:'failure',loginType:'3 · 网络登录',sourceIP:'192.0.2.52',eventCode:'4625',patternKey:'windows_login_failure',fields:{channel:'Security',record_id:84100+i,status:'0xC000006D'}});
    add('ls-windows',1200,'WARN','Special privileges assigned to new logon',{actor:'ops-admin',outcome:'privilege',loginType:'特权分配',eventCode:'4672',patternKey:'windows_privilege',fields:{channel:'Security',record_id:84039}});
    add('ls-windows',2900,'WARN','The audit log was cleared (historical sample, before this collection generation)',{actor:'audit-admin',outcome:'audit_clear',loginType:'审计日志清除',eventCode:'1102',patternKey:'audit_clear',fields:{channel:'Security',record_id:1,historical_example:true}});
    const instances=db.containers.filter(c=>c.monitorGroupId&&c.monitorGroupId===office?.monitorGroupId);
    for(let i=0;i<78;i++){const c=instances[i%Math.max(instances.length,1)]||office;if(!c)continue;add('ls-office',3500-i*40,'INFO',`request completed status=200 duration_ms=${18+i%60}`,{host:c.host,stream:c.id+'/stdout',instance:c.id,service:'v2',patternKey:'request_ok',fields:{http_status:200,route:'/api/orders'}});}
    for(let i=0;i<21;i++){const c=instances[i%Math.max(instances.length,1)]||office;if(!c)continue;add('ls-office',270-i*11,'ERROR',`upstream request timeout status=504 duration_ms=${1200+i*30}`,{host:c.host,stream:c.id+'/stderr',instance:c.id,service:'v2',traceId:i===20?'4bf92f3577b34da6a3ce929d0e0e4736':'',patternKey:'upstream_timeout',fields:{http_status:504,upstream:'db.internal.example.com:5432',route:'/api/orders',retry:2}});}
    for(let i=0;i<15;i++)add('ls-billing',3000-i*170,'INFO',`job completed batch=${8000+i}`,{instance:'c3',service:'v4',stream:'c3/stdout',patternKey:'job_ok'});
    add('ls-billing',210,'ERROR','worker memory allocation failed\n  at billing::worker::run (worker.rs:128)\n  caused by: allocation limit exceeded',{instance:'c3',service:'v4',stream:'c3/stderr',patternKey:'worker_memory',fields:{exit_code:137,note:'exit 137 单独不足以确认 OOM；需运行时 OOMKilled 证据'}});
    add('ls-billing',180,'WARN','worker restarted restart_count=3',{instance:'c3',service:'v4',stream:'c3/stderr',patternKey:'worker_restart'});
    for(let i=0;i<48;i++)add('ls-nginx',3400-i*65,'INFO',`GET /portal HTTP/1.1 status=200 bytes=${1200+i*12}`,{service:'v1',patternKey:'portal_access',fields:{http_status:200,client_ip:'192.0.2.10'}});
    add('ls-nginx',50,'ERROR','upstream timed out while reading response header from upstream',{service:'v1',traceId:'4bf92f3577b34da6a3ce929d0e0e4736',patternKey:'proxy_timeout',fields:{http_status:504,upstream:'api.internal.example.com:8080'}});
    for(let i=0;i<18;i++)add('ls-pg',3100-i*160,i%4===0?'WARN':'INFO',`statement completed duration_ms=${i%4===0?830+i:28+i}`,{service:'v3',patternKey:i%4===0?'slow_statement':'statement_ok',fields:{query_fingerprint:'SELECT … FROM orders WHERE id = $1',db:'office',sql_parameters:'[REDACTED]'}});
    for(let i=0;i<10;i++)add('ls-switch',2800-i*240,'INFO','interface GigabitEthernet1/0/24 link state UP',{patternKey:'interface_link_up',fields:{interface:'GigabitEthernet1/0/24',facility:'local7',syslog_severity:6}});
    add('ls-switch',240,'WARN','interface GigabitEthernet1/0/24 output queue discards increased',{patternKey:'queue_discards',fields:{interface:'GigabitEthernet1/0/24',facility:'local7',syslog_severity:4}});
    for(let i=0;i<8;i++)add('ls-nas',3000-i*390,'INFO',`snapshot completed volume=backup task=${900+i}`,{patternKey:'snapshot_completed'});
    for(let i=0;i<9;i++)add('ls-pve',3000-i*310,'INFO',`VM task completed vmid=${101+i} operation=backup`,{actor:'svc-backup@pve',patternKey:'vm_task',fields:{node:'pve-node-01'}});
    add('ls-system',35,'WARN','source timestamp missing: journal import example',{eventAt:null,observedAt:anchor-34000,patternKey:'missing_timestamp'});
    add('ls-system',25,'WARN','source clock ahead: sample requires time synchronization',{observedAt:anchor-28000,patternKey:'clock_skew'});
    return {anchor,sources,rows};
  }
  window.InfraLogsData={seed,anchor};
})();
