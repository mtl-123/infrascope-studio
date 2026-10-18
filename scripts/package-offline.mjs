import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, copyFile, writeFile, open, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
function run(command,args,{capture=false}={}) {
 const r=spawnSync(command,args,{cwd:root,encoding:'utf8',stdio:capture?['ignore','pipe','pipe']:['ignore','inherit','inherit']});
 if(r.error||r.status!==0)throw Error(`${command} ${args[0]} failed (${r.status??r.error?.code})`);
 return r.stdout?.trim();
}
async function hash(file){const digest=createHash('sha256');for await(const chunk of createReadStream(file))digest.update(chunk);return digest.digest('hex');}
const commit=run('git',['rev-parse','HEAD'],{capture:true});
const dirty=!!run('git',['status','--porcelain'],{capture:true});
const version='0.7.0',suffix=commit.slice(0,7)+(dirty?'-dirty':'');
const basename=`infrascope-offline-${version}-${suffix}-linux-amd64`;
const release=join(root,'release','offline'),bundle=join(release,basename);
await mkdir(release,{recursive:true});await mkdir(bundle); // Refuse overwriting an existing package.
const appImage=`infrascope-web:${version}-${suffix}-amd64`,pgImage='infrascope-postgres:18.6-amd64';
const postgres='postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873';
run('docker',['build','--platform','linux/amd64','--label',`org.opencontainers.image.revision=${commit}`,'--label','org.opencontainers.image.source=https://github.com/mtl-123/infrascope-studio','--tag',appImage,'.']);
run('docker',['pull','--platform','linux/amd64',postgres]);
run('docker',['tag',postgres,pgImage]);
const inspect=image=>JSON.parse(run('docker',['image','inspect',image],{capture:true}))[0];
const app=inspect(appImage),pg=inspect(pgImage);
if([app,pg].some(i=>i.Architecture!=='amd64'||i.Os!=='linux'))throw Error('Expected only Linux amd64 images');
for(const name of ['start.sh','stop.sh','status.sh','README.md','logrotate.example.conf']){
 await copyFile(join(root,'deploy','offline',name),join(bundle,name));
 if(name.endsWith('.sh'))await chmod(join(bundle,name),0o755);
}
const {readFile}=await import('node:fs/promises');
const compose=(await readFile(join(root,'deploy/offline/docker-compose.yml'),'utf8')).replaceAll('@APP_IMAGE@',appImage).replaceAll('@PG_IMAGE@',pgImage);
await writeFile(join(bundle,'docker-compose.yml'),compose);
await writeFile(join(bundle,'image-names.env'),`APP_IMAGE=${appImage}\nPG_IMAGE=${pgImage}\nAPP_IMAGE_ID=${app.Id}\nPG_IMAGE_ID=${pg.Id}\n`);
await writeFile(join(bundle,'VERSION.json'),JSON.stringify({version,sourceCommit:commit,dirty,platform:'linux/amd64',appImage,appImageId:app.Id,postgresImage:pgImage,postgresImageId:pg.Id,postgresSource:postgres,requiresNetworkOnTarget:false,runtimeDirectories:['config','data/postgres','logs/app','logs/postgres'],containsCredentials:false},null,2)+'\n');
console.log('Saving application and database images into the offline package…');
const imageFile=await open(join(bundle,'images.tar'),'wx');
try {
 await new Promise((resolve,reject)=>{const child=spawn('docker',['save',appImage,pgImage],{cwd:root,stdio:['ignore',imageFile.fd,'inherit']});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error(`docker save failed: ${code}`)));});
} finally {await imageFile.close();}
const imageHash=await hash(join(bundle,'images.tar'));
await writeFile(join(bundle,'images.sha256'),`${imageHash}  images.tar\n`);
const names=['start.sh','stop.sh','status.sh','README.md','logrotate.example.conf','docker-compose.yml','image-names.env','VERSION.json','images.tar','images.sha256'];
const checksums=[];for(const name of names)checksums.push(`${await hash(join(bundle,name))}  ${name}`);
await writeFile(join(bundle,'SHA256SUMS'),checksums.join('\n')+'\n');
const archive=join(release,basename+'.tar.gz');
run('tar',['-czf',archive,'-C',release,basename]);
const archiveHash=await hash(archive);
await writeFile(archive+'.sha256',`${archiveHash}  ${basename}.tar.gz\n`);
await writeFile(join(release,'latest.json'),JSON.stringify({archive,sha256:archiveHash,basename,bundle,commit,platform:'linux/amd64'},null,2)+'\n');
console.log(JSON.stringify({archive,sha256:archiveHash,platform:'linux/amd64',sourceCommit:commit,containsCredentials:false},null,2));
