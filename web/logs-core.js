(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.InfraLogsCore = api;
})(typeof window !== 'undefined' ? window : globalThis, function () {
  'use strict';
  const levels = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN'];
  const secretKey = /^(password|passwd|pwd|secret|token|access_token|refresh_token|authorization|cookie|set-cookie|api[_-]?key)$/i;
  function redact(value, depth = 0) {
    if (depth > 12) return '[DEPTH_LIMIT]';
    if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k, secretKey.test(k) ? '[REDACTED]' : redact(v, depth + 1)]));
    if (typeof value !== 'string') return value;
    return value.replace(/\b(Authorization\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s,;"}]+/gi, '$1[REDACTED]')
      .replace(/\b(password|passwd|pwd|access_token|refresh_token|token|api[_-]?key|secret)\s*([=:])\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi, '$1$2[REDACTED]')
      .replace(/\b(Cookie|Set-Cookie)\s*:\s*[^\r\n]+/gi, '$1: [REDACTED]');
  }
  function level(v) { const s=String(v||'').toUpperCase(); return ({WARNING:'WARN',ERR:'ERROR',CRIT:'FATAL',CRITICAL:'FATAL',EMERG:'FATAL',NOTICE:'INFO'})[s] || (levels.includes(s)?s:'UNKNOWN'); }
  function timestamp(r) {return Number.isFinite(r.eventAt)?r.eventAt:r.observedAt;}
  function query(text='') {
    const words=[];let word='',quoted=false,escape=false;
    for(const c of text.trim()) {if(escape){word+=c;escape=false;}else if(c==='\\'&&quoted)escape=true;else if(c==='"')quoted=!quoted;else if(/\s/.test(c)&&!quoted){if(word)words.push(word);word='';}else word+=c;}
    if(quoted||escape)return {error:'引号未闭合，请使用成对的双引号。',terms:[]};if(word)words.push(word);
    const keys={level:'level',host:'hostName',source:'sourceName',group:'groupName',service:'serviceName',trace:'traceId',actor:'actor',event:'eventCode',pattern:'patternKey'};
    const terms=[];
    for(let token of words){const not=token.startsWith('-');if(not)token=token.slice(1);let field='',value=token;const i=token.indexOf(':');if(i>0){const k=token.slice(0,i);if(!keys[k])return {error:'不支持字段 '+k+'；可用 level / host / source / group / service / trace / actor / event / pattern。',terms:[]};field=keys[k];value=token.slice(i+1);}if(!value)return {error:'搜索条件缺少值。',terms:[]};terms.push({field,value:value.toLowerCase(),not});}
    return {terms,error:''};
  }
  function matches(r, parsed){return parsed.terms.every(t=>{const hay=t.field?String(r[t.field]??''):[r.message,r.hostName,r.sourceName,r.groupName,r.instanceName,r.serviceName,r.actor,r.traceId,r.eventCode].join(' ');const hit=hay.toLowerCase().includes(t.value);return t.not?!hit:hit;});}
  function select(rows, f){
    const parsed=query(f.q||'');if(parsed.error)return {rows:[],error:parsed.error};
    if(!Number.isFinite(f.from)||!Number.isFinite(f.to)||f.from>=f.to)return {rows:[],error:'请选择有效的起止时间，结束时间必须晚于开始时间。'};
    return {error:'',rows:rows.filter(r=>timestamp(r)>=f.from&&timestamp(r)<f.to&&['host','group','service','source','env','business','level'].every(k=>!f[k]||r[k]===f[k])&&matches(r,parsed)).sort((a,b)=>timestamp(b)-timestamp(a)||b.sequence-a.sequence)};
  }
  function localTime(text){if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(text))return NaN;const n=Date.parse(text+':00+08:00');return Number.isFinite(n)&&new Date(n+28800000).toISOString().slice(0,16)===text?n:NaN;}
  function histogram(rows, from, to, count=30){const span=(to-from)/count;const bins=Array.from({length:count},(_,i)=>({from:from+i*span,to:from+(i+1)*span,total:0,errors:0}));if(!(span>0))return bins;for(const r of rows){const i=Math.floor((timestamp(r)-from)/span);if(i>=0&&i<count){bins[i].total++;if(['ERROR','FATAL'].includes(r.level))bins[i].errors++;}}return bins;}
  function pattern(message){return String(message).replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi,'<id>').replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g,'<ip>').replace(/\b0x[0-9a-f]+\b/gi,'<hex>').replace(/\b\d+\b/g,'<n>');}
  function patterns(rows){const map=new Map();for(const r of rows){const key=[r.source,r.group||r.service||r.host,r.level,r.patternKey||pattern(r.message)].join('|');if(!map.has(key))map.set(key,{key,template:pattern(r.message),sample:r,rows:[],hosts:new Set(),first:timestamp(r),last:timestamp(r)});const g=map.get(key);g.rows.push(r);g.hosts.add(r.host);g.first=Math.min(g.first,timestamp(r));g.last=Math.max(g.last,timestamp(r));}return [...map.values()].sort((a,b)=>b.rows.length-a.rows.length);}
  function context(rows, item, radius=3){return rows.filter(r=>r.source===item.source&&r.stream===item.stream&&r.generation===item.generation).sort((a,b)=>a.sequence-b.sequence).filter((r,i,a)=>Math.abs(i-a.findIndex(x=>x.id===item.id))<=radius);}
  function dedupe(existing, incoming){const ids=new Set(existing.map(r=>r.id));let duplicates=0;const rows=existing.slice();for(const r of incoming){if(ids.has(r.id)){duplicates++;continue;}ids.add(r.id);rows.push(r);}return {rows,duplicates};}
  function lag(rows){const valid=rows.filter(r=>Number.isFinite(r.eventAt)&&r.observedAt>=r.eventAt).map(r=>r.observedAt-r.eventAt).sort((a,b)=>a-b);return {p95:valid.length?valid[Math.ceil(valid.length*.95)-1]:null,valid:valid.length,skew:rows.filter(r=>Number.isFinite(r.eventAt)&&r.observedAt<r.eventAt).length,missing:rows.filter(r=>!Number.isFinite(r.eventAt)).length};}
  function rule(rule, rows, sources, end){
    const src=sources.filter(s=>!rule.source||s.id===rule.source),start=end-rule.window*60000;
    const bad=src.filter(s=>s.enabled===false||s.state==='pending'||s.state==='unsupported'||s.gap||!Number.isFinite(s.heartbeat)||s.heartbeat<end-15000||s.captureStart>start||!Number.isFinite(s.watermark)||s.watermark<end);
    if(!src.length||bad.length)return {state:'unknown',count:null,reason:!src.length?'没有可评估的日志源':'采集缺口、心跳过期或事件时间窗口尚未完整',from:start,to:end};
    const selected=select(rows,{q:rule.q,source:rule.source,from:start,to:end});if(selected.error)return {state:'unknown',count:null,reason:selected.error,from:start,to:end};
    const parsed=query(rule.q),uncertain=rows.some(r=>(!rule.source||r.source===rule.source)&&r.observedAt>=start&&r.observedAt<end&&matches(r,parsed)&&(!Number.isFinite(r.eventAt)||r.observedAt<r.eventAt));
    if(uncertain)return {state:'unknown',count:null,reason:'匹配记录存在缺失时间或时钟异常，不能确认事件时间窗口',from:start,to:end};
    const count=selected.rows.length;return {state:count>=rule.threshold?'firing':'normal',count,reason:'按事件时间评估；窗口 ['+new Date(start).toISOString()+', '+new Date(end).toISOString()+')',from:start,to:end,ids:selected.rows.map(r=>r.id)};
  }
  function parse(input, mode){
    if(new TextEncoder().encode(input).length>262144)return {error:'单条事件超过 256 KiB，请在 Agent 隔离并计数，不能静默截断。'};
    let parsed;
    try{parsed=mode==='json'?JSON.parse(input):{message:input};if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))return {error:'JSON 日志需要一个对象。'};}catch{return {error:'JSON 解析失败：保留脱敏后的文本进入隔离队列，并标记 parse_error。'};}
    const clean=redact(parsed),message=clean.message??clean.msg??clean.body??'',t=clean.timestamp||clean.time,hasZone=typeof t==='string'&&/(Z|[+-]\d{2}:\d{2})$/i.test(t),n=hasZone?Date.parse(t):NaN;
    return {value:{...clean,message,level:level(clean.level??clean.severity),event_time:Number.isFinite(n)?new Date(n).toISOString():null,time_quality:Number.isFinite(n)?'source_timestamp':'missing_or_ambiguous_use_observed',multiline_lines:input.split('\n').length},error:''};
  }
  function csv(rows){const cell=v=>{let s=String(v??'');if(/^[\s]*[=+@-]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';};const header=['event_time_utc','observed_time_utc','level','host','docker_group','instance','service','message_redacted','event_id'];return '\uFEFF'+[header,...rows.slice(0,2000).map(r=>[Number.isFinite(r.eventAt)?new Date(r.eventAt).toISOString():'',new Date(r.observedAt).toISOString(),r.level,r.hostName,r.groupName,r.instanceName,r.serviceName,redact(r.message),r.id])].map(row=>row.map(cell).join(',')).join('\r\n');}
  function health(source, at){if(source.enabled===false||['pending','unsupported','paused'].includes(source.state))return {state:'unknown',reason:'未纳入有效采集'};if(source.gap)return {state:'firing',reason:'存在未核实的采集缺口'};if(!Number.isFinite(source.heartbeat)||at-source.heartbeat>15000)return {state:'firing',reason:'采集心跳超过 15 秒未更新'};if(!Number.isFinite(source.watermark)||at-source.watermark>10000)return {state:'firing',reason:'事件时间水位落后超过 10 秒'};return {state:'normal',reason:'当前采集心跳与水位满足演示阈值'};}
  return {levels,redact,level,timestamp,query,matches,select,localTime,histogram,patterns,context,dedupe,lag,rule,health,parse,csv};
});
