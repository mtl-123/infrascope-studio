/* Start the built service against a disposable native PG database and verify real HTTPS APIs. */
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, mkdtemp, open } from 'node:fs/promises';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
await mkdir(join(root,'.local-dev'),{recursive:true,mode:0o700});
const runtime=await mkdtemp(join(root,'.local-dev/service-smoke-'));
const tls=join(runtime,'tls');await mkdir(tls,{mode:0o700});
function run(command,args,{env=process.env,input,capture=true}={}){
 const r=spawnSync(command,args,{cwd:root,env,input,encoding:'utf8',stdio:capture?['pipe','pipe','pipe']:['pipe','inherit','inherit']});
 if(r.error||r.status!==0)throw Error(`${command} ${args[0]} failed: ${r.error?.message || r.status}`);
 return r.stdout?.trim();
}
const serverSocket=createServer();await new Promise(r=>serverSocket.listen(0,'127.0.0.1',r));const port=serverSocket.address().port;await new Promise(r=>serverSocket.close(r));
const origin=`https://localhost:${port}`;
const password=randomBytes(32).toString('hex'),key=randomBytes(32).toString('base64');
const cert=join(tls,'server.crt'),privateKey=join(tls,'server.key');
run('openssl',['req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1','-keyout',privateKey,'-out',cert,'-subj','/CN=InfraScope isolated smoke','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=serverAuth']);
const admin={username:'smoke-admin',displayName:'Synthetic smoke administrator',password:randomBytes(24).toString('base64url')};
await writeFile(join(runtime,'admin.json'),JSON.stringify(admin),{mode:0o600});
await writeFile(join(runtime,'compose.env'),`REMOTE_PUBLIC_ORIGIN='${origin}'\n`,{mode:0o600});
let container,app;
try {
 container=run('docker',['run','--detach','--label','infrascope.purpose=service-smoke','--memory','256m','--cpus','1','--publish','127.0.0.1::5432','--env','POSTGRES_PASSWORD','--env','POSTGRES_DB=infrascope_smoke','postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873'],{env:{...process.env,POSTGRES_PASSWORD:password}});
 let ready=false;
 for(let i=0;i<80;i++){
  if(spawnSync('docker',['exec',container,'pg_isready','-h','127.0.0.1','-U','postgres','-d','infrascope_smoke'],{stdio:'ignore'}).status===0){ready=true;break;}
  await new Promise(r=>setTimeout(r,250));
 }
 if(!ready)throw Error('Isolated PostgreSQL did not become ready');
 const address=run('docker',['port',container,'5432/tcp']);if(!/^127\.0\.0\.1:\d+$/.test(address))throw Error('Database not bound only to loopback');
 const env={...process.env,REMOTE_ENABLED:'true',REMOTE_LISTEN:`127.0.0.1:${port}`,REMOTE_PUBLIC_ORIGIN:origin,REMOTE_STATIC_DIR:join(root,'build/service/web'),REMOTE_TLS_CERT:cert,REMOTE_TLS_KEY:privateKey,REMOTE_WORKSPACE:'isolated-build-smoke',REMOTE_GATEWAY_ID:'isolated-build-smoke',REMOTE_ALLOWED_CIDRS:'',REMOTE_SECRET_KEYS:JSON.stringify({'smoke-key':key}),REMOTE_ACTIVE_KEY_VERSION:'smoke-key',DATABASE_URL:`postgres://postgres:${password}@${address}/infrascope_smoke?sslmode=disable`};
 const binary=join(root,'build/service',process.platform==='win32'?'infrascope.exe':'infrascope');
 run(binary,['migrate'],{env});run(binary,['bootstrap'],{env,input:JSON.stringify(admin)});
 const log=await open(join(runtime,'server.log'),'a',0o600);app=spawn(binary,['serve'],{cwd:root,env,stdio:['ignore',log.fd,log.fd]});await log.close();
 run(process.execPath,['scripts/smoke-compose.mjs'],{capture:false,env:{...process.env,INFRASCOPE_RUNTIME_DIR:runtime}});
 console.log('PASS: generated build/service bundle started with migrations, bootstrap, real PG and authenticated HTTPS APIs. No development secrets were used.');
} finally {
 if(app&&app.exitCode===null){app.kill('SIGTERM');await Promise.race([new Promise(r=>app.once('exit',r)),new Promise(r=>setTimeout(r,2000))]);if(app.exitCode===null)app.kill('SIGKILL');}
 if(container&&run('docker',['inspect','--format','{{index .Config.Labels "infrascope.purpose"}}',container])==='service-smoke')run('docker',['rm','--force',container]);
}
