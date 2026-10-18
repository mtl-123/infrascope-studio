import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root=fileURLToPath(new URL('../',import.meta.url));
const mode=process.argv[2];
if(!['up','down','ps','logs'].includes(mode))throw Error('Usage: node scripts/compose.mjs up|down|ps|logs');
const envFile=join(root,'.runtime/compose.env');
if(!existsSync(envFile))throw Error('Run npm run setup first. Existing deployments must restore their original .runtime secrets.');
const base=['compose','--project-directory',root,'--env-file',envFile,'-f',join(root,'compose.yaml')];
function run(args,{capture=false,input}={}) {
 const result=spawnSync('docker',[...base,...args],{cwd:root,encoding:'utf8',stdio:capture?['pipe','pipe','pipe']:['pipe','inherit','inherit'],input});
 if(result.error||result.status!==0)throw Error(`docker compose ${args[0]} failed (${result.status??result.error?.code}); inspect the service logs; data and secrets were retained`);
 return result.stdout?.trim();
}
if(mode==='up') {
 run(['build','app']);
 run(['up','-d','--wait','db']);
 run(['stop','app']);
 run(['run','--rm','--no-deps','app','migrate']);
 const users=run(['exec','-T','db','psql','-U','postgres','-d','infrascope','-Atc','SELECT count(*) FROM ra_users'],{capture:true});
 if(users==='0')run(['run','--rm','--no-deps','-T','app','bootstrap'],{input:await readFile(join(root,'.runtime/admin.json'),'utf8')});
 else if(!/^\d+$/.test(users))throw Error('Cannot confirm bootstrap state; no administrator was created');
 run(['up','-d','app']);
 run(['ps']);
 console.log('Started. HTTPS origin is configured in .runtime/compose.env; private admin credentials are in .runtime/admin.json');
} else if(mode==='down')run(['down']);
else if(mode==='logs')run(['logs','--tail','100','app']);
else run(['ps']);
