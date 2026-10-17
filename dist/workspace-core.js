(function(global){
'use strict';
const groupName=c=>(c.dockerName||c.composeService||c.name||'未命名 Docker').trim();
const groupScope=c=>JSON.stringify([c.environment||'未分类',c.business||'未归属',c.project||'独立部署',groupName(c)]);
const groupId=c=>c.monitorGroupId||groupScope(c);
function groups(containers){const map=new Map();for(const c of containers){const name=groupName(c),id=groupId(c);if(!map.has(id))map.set(id,{id,name,environment:c.environment||'未分类',project:c.project||'独立部署',instances:[],hosts:[],businesses:[]});const g=map.get(id);g.instances.push(c);if(!g.hosts.includes(c.host))g.hosts.push(c.host);if(!g.businesses.includes(c.business))g.businesses.push(c.business);}return [...map.values()].map(g=>({...g,abnormal:g.instances.filter(c=>/异常|失败|OOM/.test(c.state)).length,unknown:g.instances.filter(c=>/待|未知|未检查/.test(c.state)).length,cpu:g.instances.some(c=>c.cpu!=null)?g.instances.reduce((n,c)=>n+(Number(c.cpu)||0),0):null})).sort((a,b)=>b.abnormal-a.abnormal||a.name.localeCompare(b.name));}
function valid(r,now){return r.quality==='valid'&&Number.isFinite(r.rx)&&Number.isFinite(r.tx)&&Number.isFinite(r.at)&&now-r.at<=10000;}
function rank(rows,sort='total',now=Date.now()){return [...rows].sort((a,b)=>{const av=valid(a,now),bv=valid(b,now);if(av!==bv)return av?-1:1;if(!av)return a.id.localeCompare(b.id);const val=r=>sort==='rx'?r.rx:sort==='tx'?r.tx:r.rx+r.tx;return val(b)-val(a)||a.id.localeCompare(b.id);});}
function groupKey(name){return 'dockerGroups:'+name+':restart';}
function searchPeople(people,query){const q=query.trim().replace(/^@/,'').toLocaleLowerCase();return people.filter(p=>p.active!==false&&[p.name,p.department,p.id,p.pinyin||''].join(' ').toLocaleLowerCase().includes(q));}
function uniquePeople(ids,people){return [...new Set(ids)].filter(id=>people.some(p=>p.id===id&&p.active!==false));}
const api={groupName,groupScope,groupId,groups,rank,valid,groupKey,searchPeople,uniquePeople};if(typeof module!=='undefined')module.exports=api;else global.InfraWorkspaceCore=api;
})(typeof window!=='undefined'?window:globalThis);
