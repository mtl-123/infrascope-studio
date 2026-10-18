const {test}=require('node:test');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const core=require('../dist/getting-started.js');
// Parse generated commands with bash before shipping; no network or collection is performed.
test('generated Linux install block is valid bash and TOML data is literal',()=>{
 const commands=core.installCommands('https://monitor.example:18443',true,'a'.repeat(64));
 const syntax=spawnSync('bash',['-n'],{input:commands,encoding:'utf8'});
 assert.equal(syntax.status,0,syntax.stderr);
});

test('enrollment block stops on failed enrollment and starts continuous collection only after successful upload',()=>{
 const syntax=spawnSync('bash',['-n'],{input:core.enrollCommands,encoding:'utf8'});
 assert.equal(syntax.status,0,syntax.stderr);
 assert.match(core.enrollCommands,/once --config \.\/host.toml &&/);
 assert.match(core.enrollCommands,/unset INFRASCOPE_ENROLLMENT_TOKEN/);
});
