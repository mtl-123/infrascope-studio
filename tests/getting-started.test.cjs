const { test } = require('node:test');
const assert = require('node:assert/strict');
const core = require('../dist/getting-started.js');
const vm = require('node:vm');
const fs = require('node:fs');
const source = fs.readFileSync(require.resolve('../dist/getting-started.js'), 'utf8');
const now = Date.now();
const agent = {id:'a1',kind:'host',os:'linux',enabled:true,revoked:false,intervalSeconds:5};
const sample = {agentId:'a1',kind:'host',receivedAt:new Date(now).toISOString(),observedAt:new Date(now).toISOString(),health:{status:'ok'}};
const result = (a=agent,s=sample) => ({agents:[a], samples:s?[s]:[]});
test('remote machines are blocked on loopback origins while same Linux HTTPS is allowed',()=>{
  for(const host of ['127.0.0.1','localhost','[::1]']) {
    assert.match(core.connection('https://'+host+':18443','remote'),/无法连接/);
    assert.equal(core.connection('https://'+host+':18443','local'),'');
  }
  assert.match(core.connection('http://monitor.example','remote'),/HTTPS/);
  assert.equal(core.connection('https://monitor.example','remote'),'');
});
test('generated TOML is an exact HTTPS origin, optional CA, no credentials or shell interpolation',()=>{
  const text=core.config('https://monitor.example:18443',true);
  assert.match(text,/ca_cert = ".\/server-ca.pem"/);
  assert.match(text,/allow_insecure_loopback = false/);
  assert.doesNotMatch(core.config('https://monitor.example',false),/ca_cert/);
  for(const origin of ['http://monitor.example','https://monitor.example/path','https://u:p@monitor.example']) assert.throws(()=>core.config(origin,true));
  const commands=core.installCommands('https://monitor.example',true,'d'.repeat(64));
  assert.match(commands,/sha256sum -c/); assert.match(commands,/<<'INFRASCOPE_CONFIG'/);
  assert.doesNotMatch(commands,/curl.*-k|PRIVATE KEY|ENROLLMENT_TOKEN=/);
});
test('existing registered agents and samples never auto-complete a new wizard',()=>{
  assert.equal(core.evaluate(result(),'',now-1000,now).state,'waiting');
  assert.equal(core.evaluate(result(),'a1',now+1000,now).state,'registered');
  assert.equal(core.evaluate(result({...agent,os:'windows'}),'a1',now-1000,now).state,'waiting');
});
test('completion requires matching live Linux identity, current receipt, fresh observation and healthy collector',()=>{
  assert.equal(core.evaluate(result(),'a1',now-1000,now).state,'ready');
  assert.equal(core.evaluate(result({...agent,revoked:true}),'a1',now-1000,now).state,'blocked');
  assert.equal(core.evaluate(result({...agent,enabled:false}),'a1',now-1000,now).state,'blocked');
  assert.equal(core.evaluate(result(agent,{...sample,agentId:'a2'}),'a1',now-1000,now).state,'registered');
  assert.equal(core.evaluate(result(agent,{...sample,health:{status:'partial'}}),'a1',now-1000,now).state,'partial');
  for(const observedAt of [new Date(now-120000).toISOString(),new Date(now+120000).toISOString(),'invalid']) assert.equal(core.evaluate(result(agent,{...sample,observedAt}),'a1',now-1000,now).state,'stale');
});
class Element {
  constructor(){this.children=new Map();this.disabled=false;this.isConnected=true;this.dataset={};this.classList={remove(){}};this.value='';}
  set innerHTML(value){this.html=value;this.children.clear();}
  get innerHTML(){return this.html||'';}
  querySelector(key){if(!this.children.has(key))this.children.set(key,new Element());return this.children.get(key);}
  querySelectorAll(){return [];}
  focus(){}
}
function runtime(handler){
  const target=new Element(),calls=[],timers=new Map(); let timerId=0,valid=true;
  const context=vm.createContext({window:{},URL,TextEncoder,Date,console,
    location:{origin:'https://127.0.0.1:18443'},document:{visibilityState:'visible'},
    navigator:{clipboard:{writeText:async()=>{}}},
    fetch:async()=>({ok:true,json:async()=>({linux:true,ca:true,sha256:'d'.repeat(64)})}),
    setTimeout:(fn)=>{timers.set(++timerId,fn);return timerId;},clearTimeout:id=>timers.delete(id),
    FormData:class {constructor(form){return form.data;}}
  });
  vm.runInContext(source,context);
  const api=context.window.InfraOnboarding;
  const user={id:'u1',role:'admin',permissions:['asset.manage']};
  const ctx={user,current:()=>valid,details:async()=>{},api:async(url,method='GET',body)=>{
    calls.push({url,method,body});const override=handler&&await handler(url,method,body);if(override!==undefined)return override;
    if(url.startsWith('/api/v1/assets?'))return [];
    if(url.startsWith('/people?'))return [{id:'p1',display_name:'Real contact',enabled:true}];
    if(url==='/people')return {id:'p2'};
    if(url==='/api/v1/assets')return {id:'new-asset'};
    if(url==='/api/v1/agents/enrollments')return {token:'synthetic-token',expiresAt:new Date(Date.now()+600000).toISOString()};
    if(url.includes('/telemetry'))return {agents:[],samples:[]};
    throw Error('unexpected '+url);
  }};
  const submit=async values=>{const form=target.querySelector('#guide-asset-form');form.id='guide-asset-form';form.data=new Map(Object.entries(values)); await target.onsubmit({target:form,preventDefault(){}});};
  const click=async action=>{const b=new Element();b.dataset.guide=action;await target.onclick({target:{closest:()=>b}});};
  return {api,target,ctx,calls,timers,submit,click,invalidate:()=>{valid=false;}};
}
const values={name:'Linux test',kind:'virtual',person:'p1',confirm:'on'};
test('wizard does not mutate until confirmation, and uses only asset/contact/enrollment APIs',async()=>{
  const e=runtime();await e.api.mount(e.target,e.ctx);
  await e.submit(values);
  assert.ok(e.calls.some(c=>c.url==='/api/v1/assets'));
  const saved=e.calls.find(c=>c.url==='/api/v1/assets');
  assert.equal(saved.body.osFamily,'linux'); assert.equal(saved.body.ownership.userId,'p1'); assert.equal(saved.body.endpoints.length,0);
  assert.ok(e.target.innerHTML.includes('2. 检查连接与下载'));
  assert.equal(e.target.querySelector('[data-guide="connection-next"]').disabled,true);
  assert.ok(!e.calls.some(c=>/accounts|grants|onboard/.test(c.url)));
  e.api.leave();
});
test('missing confirmation prevents every write',async()=>{
  const e=runtime();await e.api.mount(e.target,e.ctx);const input={...values};delete input.confirm;await e.submit(input);
  assert.equal(e.calls.filter(c=>c.method==='POST').length,0);assert.match(e.target.querySelector('[data-guide-error]').textContent,/确认/);e.api.leave();
});
test('inline contact survives a rejected asset save without duplicate creation',async()=>{
  let attempts=0; const e=runtime((url,method)=>{if(url==='/api/v1/assets'&&method==='POST'&&++attempts===1)throw Object.assign(Error('invalid asset'),{status:400});});
  await e.api.mount(e.target,e.ctx); const input={...values,person:'',contactName:'New person'};
  await e.submit(input);await e.submit(input);
  assert.equal(e.calls.filter(c=>c.url==='/people'&&c.method==='POST').length,1);
  assert.equal(e.calls.filter(c=>c.url==='/api/v1/assets'&&c.method==='POST').length,2);e.api.leave();
});
test('ambiguous asset write is not retried automatically',async()=>{
  const e=runtime((url,method)=>{if(url==='/api/v1/assets'&&method==='POST')throw Error('network lost');});
  await e.api.mount(e.target,e.ctx);await e.submit(values);await e.submit(values);
  assert.equal(e.calls.filter(c=>c.url==='/api/v1/assets'&&c.method==='POST').length,1);
  assert.match(e.target.querySelector('[data-guide-error]').textContent,/响应未确认/);e.api.leave();
});
test('late asset response after navigation cannot advance or expose a new token',async()=>{
  let resolve;const wait=new Promise(r=>resolve=r);const e=runtime((url,method)=>url==='/api/v1/assets'&&method==='POST'?wait:undefined);
  await e.api.mount(e.target,e.ctx);const pending=e.submit(values);await Promise.resolve();await Promise.resolve();e.invalidate();e.api.leave();resolve({id:'saved-after-leave'});await pending;
  assert.ok(!e.target.innerHTML.includes('2. 检查连接与下载'));assert.equal(e.target.onclick,null);assert.equal(e.timers.size,0);
});
test('non-managers cannot fetch directories or start onboarding',async()=>{
  const e=runtime();e.ctx.user.permissions=[];await e.api.mount(e.target,e.ctx);assert.equal(e.calls.length,0);assert.match(e.target.innerHTML,/需要资产管理权限/);
});
test('duplicate submit is locked while first save is pending',async()=>{
  let resolve;const pending=new Promise(r=>resolve=r);const e=runtime((url,method)=>url==='/api/v1/assets'&&method==='POST'?pending:undefined);
  await e.api.mount(e.target,e.ctx);const first=e.submit(values);await e.submit(values);resolve({id:'one-asset'});await first;
  assert.equal(e.calls.filter(c=>c.url==='/api/v1/assets'&&c.method==='POST').length,1);e.api.leave();
});
test('token display and timers are erased when leaving the page',async()=>{
  const e=runtime();await e.api.mount(e.target,e.ctx);await e.submit(values);
  e.target.onchange({target:{name:'mode',value:'local'}});e.target.querySelector('[name="reachable"]').checked=true;await e.click('connection-next');await e.click('token');
  assert.match(e.target.querySelector('[data-guide-token]').innerHTML,/synthetic-token/);assert.ok(e.timers.size>0);
  const token=e.target.querySelector('[data-guide-token]');e.api.leave();assert.equal(token.textContent,'');assert.equal(e.timers.size,0);assert.equal(e.target.onclick,null);
});
