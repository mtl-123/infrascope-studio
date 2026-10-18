import { spawnSync } from 'node:child_process';
import { readFile, writeFile, mkdir, mkdtemp, access, stat } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { request } from 'node:https';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const metadata=JSON.parse(await readFile(join(root,'release/offline/latest.json'),'utf8'));
await mkdir(join(root,'.local-dev'),{recursive:true,mode:0o700});
const isolated=await mkdtemp(join(root,'.local-dev/offline-deployment-'));
function run(command,args,{capture=false,cwd=root}={}){const r=spawnSync(command,args,{cwd,encoding:'utf8',stdio:capture?['pipe','pipe','pipe']:['ignore','inherit','inherit']});if(r.error||r.status!==0)throw Error(`${command} ${args[0]} failed: ${r.status??r.error?.message}`);return r.stdout?.trim();}
run('tar',['-xzf',metadata.archive,'-C',isolated]);
const bundle=join(isolated,metadata.basename),project='offline-test-'+randomBytes(4).toString('hex');
let cookie='',csrf='';const origin='https://127.0.0.1:18447';let ca;
async function api(path,method='GET',data){const body=data===undefined?undefined:JSON.stringify(data);const result=await new Promise((resolve,reject)=>{
 const req=request(origin+path,{method,ca,headers:{Origin:origin,Cookie:cookie,'X-CSRF-Token':csrf,...(body?{'Content-Type':'application/json'}:{})}},res=>{const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,text:Buffer.concat(chunks).toString()}));});req.setTimeout(10000,()=>req.destroy(Error('HTTPS timeout')));req.on('error',reject);req.end(body);
});if(![200,201].includes(result.status))throw Error(`${path}: HTTP ${result.status}`);if(result.headers['set-cookie'])cookie=result.headers['set-cookie'].map(v=>v.split(';')[0]).join('; ');return JSON.parse(result.text);}
async function login(){const admin=JSON.parse(await readFile(join(bundle,'config/admin.json'),'utf8'));await api('/api/remote-access/auth/login','POST',{username:admin.username,password:admin.password});csrf=(await api('/api/remote-access/auth/me')).csrf;}
const summary={platform:'linux/amd64',sourceCommit:metadata.commit,checks:[],status:'FAIL'};
try{
 run('sha256sum',['-c','SHA256SUMS'],{cwd:bundle});summary.checks.push('archive contents verified');
 // The deployment must import the archived tags, rather than depend on already-loaded tags.
 const images=JSON.parse(await readFile(join(bundle,'VERSION.json'),'utf8'));
 run('docker',['image','rm',images.appImage,images.postgresImage],{capture:true});
 run('./start.sh',['--host','127.0.0.1','--port','18447','--bind','127.0.0.1','--project',project],{cwd:bundle});
 summary.checks.push('docker load from archive and compose with pull_policy never');
 ca=await readFile(join(bundle,'config/server-ca.crt'));await login();
 await api('/api/remote-access/health');await api('/api/v1/agents');
 const person=await api('/api/remote-access/people','POST',{displayName:'Offline synthetic contact',contactType:'internal',enabled:true});
 const asset=await api('/api/v1/assets','POST',{name:'Offline persistence test',category:'server',kind:'virtual',osFamily:'linux',enabled:true,endpoints:[],ownership:{state:'assigned',userId:person.id}});
 summary.checks.push('TLS, first administrator, canonical contact and asset APIs');
 const keysBefore=createHash('sha256').update(await readFile(join(bundle,'config/app.env'))).update(await readFile(join(bundle,'config/admin.json'))).digest('hex');
 run('./stop.sh',[],{cwd:bundle});run('./start.sh',[],{cwd:bundle});
 cookie='';csrf='';await login();const assets=await api('/api/v1/assets');if(!assets.some(a=>a.id===asset.id))throw Error('Asset did not survive stop/start');
 const keysAfter=createHash('sha256').update(await readFile(join(bundle,'config/app.env'))).update(await readFile(join(bundle,'config/admin.json'))).digest('hex');if(keysBefore!==keysAfter)throw Error('Secrets were changed during restart');
 summary.checks.push('stop/start preserved database, administrator and AES key');
 if((await stat(join(bundle,'logs/app/service.log'))).size===0)throw Error('Application log is empty');
 const ids=run('docker',['compose','--env-file','config/deploy.env','-f','docker-compose.yml','ps','-q'],{cwd:bundle,capture:true}).split(/\s+/).filter(Boolean);
 for(const id of ids){const item=JSON.parse(run('docker',['inspect',id],{capture:true}))[0];for(const mount of item.Mounts){if(mount.Type==='tmpfs'&&mount.Destination==='/tmp')continue;if(mount.Type!=='bind'||!mount.Source.startsWith(bundle+'/'))throw Error('Runtime state is outside the deployment directory');}}
 summary.checks.push('configuration, data and log mounts are only under the current directory');
 summary.status='PASS';
}catch(error){
 try{run('docker',['compose','--env-file','config/deploy.env','-f','docker-compose.yml','logs','--tail','60','db'],{cwd:bundle});}catch{}
 throw error;
}finally{
 try{await access(join(bundle,'config/deploy.env'));run('./stop.sh',[],{cwd:bundle});summary.cleanup='PASS';}catch{summary.cleanup='NOT_CONFIRMED';}
 await writeFile(join(root,'release/offline/TEST-REPORT.json'),JSON.stringify(summary,null,2)+'\n');
 console.log(JSON.stringify(summary,null,2));
}
