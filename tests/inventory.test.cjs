const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
// Exercise data validation, state transitions and rendering without a browser.
// Actual DOM interactions and layout still require browser QA.
const source=fs.readFileSync('dist/inventory.js','utf8').replace('window.InfraInventory={render};','window.InfraInventory={render};window.test={db,render,draw,submitForm,probe,detail,portData,validHost,isIP,esc,set:(p,id)=>{active=p;selected=id;}};');
const list={innerHTML:''},feedback={textContent:''},breadcrumb={textContent:''},probeInput={value:'ok'};
const content={dataset:{},innerHTML:'',querySelector:s=>s==='#iv-probe-result'?probeInput:list};
const root={querySelector:s=>({'#io-content':content,'#io-feedback':feedback,'#studio-breadcrumb':breadcrumb}[s]),querySelectorAll:()=>[],addEventListener:()=>{}};
const store={};const ctx={document:{getElementById:()=>root},window:{addEventListener:()=>{}},location:{hash:''},history:{replaceState:()=>{}},localStorage:{getItem:k=>store[k],setItem:(k,v)=>store[k]=v},structuredClone,URL,FormData:class{constructor(f){return Object.entries(f.values)}},console};vm.createContext(ctx);vm.runInContext(source,ctx);const t=ctx.window.test;
for(const p of ['devices','containers','services','switches']){t.render(p);assert.match(content.innerHTML,/交互演示/);assert.match(list.innerHTML,/<table>/);}
for(const [p,rows] of Object.entries({devices:t.db.servers,containers:t.db.containers,services:t.db.services,switches:t.db.switches})){t.set(p,null);for(const r of rows){assert.ok(t.detail(r).length>400);}}
assert.ok(t.isIP('10.20.1.40'));assert.ok(t.isIP('2001:db8::1'));assert.ok(!t.isIP('999.1.1.1'));assert.ok(!t.isIP('10.0.00.1'));
assert.ok(t.validHost('portal.example.com'));assert.ok(!t.validHost('https://portal.example.com:443'));assert.ok(!t.validHost('10.300.1.1'));assert.ok(!t.validHost('bad host'));assert.equal(t.esc('<img onerror="x">'),'&lt;img onerror=&quot;x&quot;&gt;');
function submit(page,list,values,maps=[],old=null){t.set(page,null);const error={textContent:''};const f={values,querySelectorAll:()=>maps.map(m=>({querySelector:s=>({value:m[s.match(/"(\w+)"/)[1]]})}))};const d={closed:false,querySelector:s=>s==='form'?f:error,close(){this.closed=true;}};t.submitForm(d,list,old);return {d,error:error.textContent};}
const server={name:'test-vm',kind:'虚拟机',os:'Windows',version:'Windows Server 2022',ip:'10.20.1.40',port:'3389',env:'测试',business:'测试业务',owner:'QA',cpu:'4',ram:'8',disk:'120',hypervisor:'PVE',parent:'pve-node-01',vmid:'104'};
assert.ok(submit('devices','servers',{...server,ip:'999.1.1.1'}).error);
assert.ok(submit('devices','servers',{...server,ip:'10.20.1.11'}).error);
assert.ok(submit('devices','servers',server).d.closed);const added=t.db.servers.at(-1);assert.equal(added.state,'待接入');assert.equal(added.cpuUse,null);assert.equal(added.hypervisor,'PVE');assert.ok(submit('devices','servers',server).error);
const container={name:'test-container',host:'s1',network:'bridge',image:'test:1',business:'测试业务',project:'test',health:''};
assert.ok(submit('containers','containers',container,[{host:'8080',container:'80',protocol:'TCP'}]).error);
assert.ok(submit('containers','containers',container,[{host:'8088',container:'80',protocol:'TCP'},{host:'8088',container:'81',protocol:'TCP'}]).error);
assert.ok(submit('containers','containers',{...container,host:added.id},[{host:'8088',container:'80',protocol:'TCP'}]).d.closed);const c=t.db.containers.at(-1);assert.equal(c.host,added.id);assert.equal(c.state,'待发现');
const service={name:'test-service',business:'测试业务',target:c.id,protocol:'HTTPS',domain:'test.example.com',listen:'80',port:'443',path:'/health',expected:'200',interval:'10',timeout:'3',fail:'3',recover:'2',collector:'机房 A · collector-01'};
assert.ok(submit('services','services',{...service,timeout:'10'}).error);assert.ok(submit('services','services',{...service,path:'health'}).error);assert.ok(submit('services','services',service).d.closed);const svc=t.db.services.at(-1);assert.equal(svc.state,'未检测');assert.equal(svc.target,c.id);
t.set('services',svc.id);probeInput.value='ok';t.probe(svc.id);assert.equal(svc.state,'正常');probeInput.value='fail';t.probe(svc.id);assert.equal(svc.state,'待确认');t.probe(svc.id);assert.equal(svc.state,'待确认');t.probe(svc.id);assert.equal(svc.state,'异常');probeInput.value='ok';t.probe(svc.id);assert.equal(svc.state,'恢复中');probeInput.value='fail';t.probe(svc.id);assert.equal(svc.state,'异常','Interrupted recovery must preserve firing incident');probeInput.value='ok';t.probe(svc.id);assert.equal(svc.state,'恢复中');t.probe(svc.id);assert.equal(svc.state,'正常');assert.equal(svc.history.length,8);
const sw={name:'test-switch',ip:'10.20.0.99',vendor:'H3C',model:'test',ports:'24',speed:'1 Gbps',uplink:'10 Gbps',udp:'161',user:'monitor-ro',auth:'SHA-256',privacy:'AES-128',credential:'vault://network/test',interval:'10',business:'测试',location:'机房 B',collector:'机房 A · collector-01',syslog:'未配置',trap:'未配置'};
assert.ok(submit('switches','switches',{...sw,credential:'secret-password'}).error);assert.ok(submit('switches','switches',sw).d.closed);const w=t.db.switches.at(-1);assert.equal(t.portData(w,1).state,'未知');assert.equal(t.portData(w,1).rx,'—');assert.equal(w.state,'待接入');
assert.ok(Object.values(store).some(s=>s.includes('test-vm')&&s.includes('test-service')));
console.log('PASS: rendering smoke, IPv4/IPv6, escaping, duplicate IP/ports, object associations, unknown states, detection thresholds, interrupted recovery and persistence. Browser layout not tested.');
