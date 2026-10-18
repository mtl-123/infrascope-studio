import { request } from 'node:https';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url));
const runtime=process.env.INFRASCOPE_RUNTIME_DIR || join(root,'.runtime');
const text=await readFile(join(runtime,'compose.env'),'utf8');
const origin=text.match(/^REMOTE_PUBLIC_ORIGIN='([^']+)'$/m)?.[1];
if(!origin)throw Error('No configured origin');
const ca=await readFile(join(runtime,'tls/server.crt'));
const admin=JSON.parse(await readFile(join(runtime,'admin.json'),'utf8'));
let cookie='',csrf='';
async function get(path,method='GET',data) {
 const body=data===undefined?undefined:JSON.stringify(data);
 const r=await new Promise((resolve,reject)=>{
  const req=request(origin+path,{method,ca,headers:{Origin:origin,Cookie:cookie,'X-CSRF-Token':csrf,...(body?{'Content-Type':'application/json'}:{})}},res=>{const parts=[];res.on('data',p=>parts.push(p));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(parts).toString()}));});
  req.setTimeout(10000,()=>req.destroy(Error('HTTPS request timeout')));req.on('error',reject);req.end(body);
 });
 if(r.status!==200)throw Error(`${method} ${path}: HTTP ${r.status}`);
 if(r.headers['set-cookie'])cookie=r.headers['set-cookie'].map(c=>c.split(';')[0]).join('; ');
 return r;
}
let ready=false;
for(let i=0;i<30;i++){try{await get('/');ready=true;break;}catch{await new Promise(r=>setTimeout(r,500));}}
if(!ready)throw Error('Compose HTTPS did not become ready');
await get('/api/remote-access/auth/login','POST',{username:admin.username,password:admin.password});
csrf=JSON.parse((await get('/api/remote-access/auth/me')).body).csrf;
for(const path of ['/api/remote-access/health','/api/v1/assets','/api/v1/agents','/getting-started.js'])await get(path);
await get('/api/remote-access/auth/logout','POST',{});
console.log('PASS: HTTPS certificate, administrator bootstrap, authenticated health/assets/agents and frontend bundle');
