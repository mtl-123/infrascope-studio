import { prepareOnboarding } from "./prepare-onboarding.mjs";
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, writeFile, chmod, readFile, chown } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const { values } = parseArgs({ options: { port: {type:'string',default:'18443'}, project: {type:'string',default:'infrascope'}, origin: {type:'string'}, bind:{type:'string',default:'127.0.0.1'} } });
const port = Number(values.port);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('--port must be 1..65535');
if (!/^[a-z][a-z0-9_-]{0,50}$/.test(values.project)) throw Error('Invalid Compose project name');
if (!['127.0.0.1','0.0.0.0'].includes(values.bind)) throw Error('--bind must be 127.0.0.1 or explicit 0.0.0.0');
const origin = values.origin || `https://localhost:${port}`, url = new URL(origin);
if (url.protocol !== 'https:' || url.origin !== origin || url.username || url.password) throw Error('--origin must be an exact HTTPS origin');
if (!/^[A-Za-z0-9.:[\]-]+$/.test(url.hostname)) throw Error('Invalid DNS/IP hostname in origin');
if (url.port !== String(port) && !(port===443&&!url.port)) throw Error('Origin port must match --port');
if (values.bind === '0.0.0.0' && (!values.origin || ['localhost','127.0.0.1','[::1]'].includes(url.hostname))) throw Error('Remote binding requires a reachable --origin with matching TLS certificate');
const runtimeUID = process.getuid?.() === 0 ? 10001 : (process.getuid?.() ?? 10001);
const runtimeGID = process.getuid?.() === 0 ? 10001 : (process.getgid?.() ?? 10001);
const directory = join(root,'.runtime'), tls = join(directory,'tls');
const envPath = join(directory,'compose.env'), adminPath = join(directory,'admin.json');
await mkdir(tls,{recursive:true,mode:0o700});await chmod(directory,0o700);await chmod(tls,0o700);
const hasEnv=existsSync(envPath),hasAdmin=existsSync(adminPath);
if (hasEnv !== hasAdmin) throw Error('Runtime configuration is incomplete. Restore the matching configuration and credentials; do not regenerate encryption keys.');
if (!hasEnv) {
  const password = randomBytes(32).toString('hex'), key = randomBytes(32).toString('base64');
  const env = {COMPOSE_PROJECT_NAME:values.project,INFRASCOPE_BIND:values.bind,INFRASCOPE_HTTPS_PORT:String(port),INFRASCOPE_UID:String(runtimeUID),INFRASCOPE_GID:String(runtimeGID),POSTGRES_PASSWORD:password,DATABASE_URL:`postgres://postgres:${password}@db:5432/infrascope?sslmode=disable`,REMOTE_PUBLIC_ORIGIN:origin,REMOTE_WORKSPACE:'default',REMOTE_GATEWAY_ID:'gateway-1',REMOTE_ALLOWED_CIDRS:'',REMOTE_SECRET_KEYS:JSON.stringify({'key-1':key}),REMOTE_ACTIVE_KEY_VERSION:'key-1'};
  // Values are generated or validated above; dotenv literals preserve the JSON keyring.
  await writeFile(envPath,Object.entries(env).map(([k,v])=>`${k}='${v}'`).join('\n')+'\n',{mode:0o600,flag:'wx'});
  await writeFile(adminPath,JSON.stringify({username:'admin',displayName:'InfraScope Administrator',password:randomBytes(24).toString('base64url')},null,2)+'\n',{mode:0o600,flag:'wx'});
} else console.log('Existing database password, administrator and encryption keys retained. Existing compose.env settings take precedence over setup flags.');
const savedOrigin = (await readFile(envPath,'utf8')).match(/^REMOTE_PUBLIC_ORIGIN='([^']+)'$/m)?.[1];
const certURL = new URL(savedOrigin || origin);
const cert=join(tls,'server.crt'),key=join(tls,'server.key');
if (existsSync(cert)!==existsSync(key)) throw Error('TLS certificate and key must both exist. Restore the pair.');
const run=args=>{const r=spawnSync('openssl',args,{stdio:['ignore','pipe','pipe']});if(r.error||r.status!==0)throw Error('OpenSSL failed. Install OpenSSL or restore a valid TLS certificate/key pair.');return r.stdout;};
if (!existsSync(cert)) {
  const sans=['DNS:localhost','IP:127.0.0.1','IP:::1'];
  if (!['localhost','127.0.0.1','[::1]'].includes(certURL.hostname)) {
    if (!/^[a-zA-Z0-9.-]+$/.test(certURL.hostname))throw Error('For IPv6/custom SANs install your own certificate pair');
    sans.push(/^\d+\.\d+\.\d+\.\d+$/.test(certURL.hostname)?`IP:${certURL.hostname}`:`DNS:${certURL.hostname}`);
  }
  run(['req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','30','-keyout',key,'-out',cert,'-subj','/CN=InfraScope Development','-addext','subjectAltName='+sans.join(','),'-addext','basicConstraints=critical,CA:FALSE','-addext','extendedKeyUsage=serverAuth']);
}
run(['x509','-in',cert,'-checkend','86400','-noout']);
if (!run(['x509','-in',cert,'-pubkey','-noout']).equals(run(['pkey','-in',key,'-pubout']))) throw Error('TLS certificate and key do not match');
await chmod(cert,0o644);await chmod(key,0o600);
if (process.getuid?.() === 0) {
  await chown(tls,runtimeUID,runtimeGID); await chown(cert,runtimeUID,runtimeGID); await chown(key,runtimeUID,runtimeGID);
}
await prepareOnboarding({ staticRoot: directory, certificate: cert });
console.log('Prepared .runtime/ (private, ignored by Git). Admin credentials: .runtime/admin.json');
console.log('Next: npm run up. Trust the local public certificate explicitly if needed; TLS checks are never disabled.');
