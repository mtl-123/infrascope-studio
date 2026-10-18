import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile, open, copyFile, chmod } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';

const root = fileURLToPath(new URL('../', import.meta.url));
const runId = new Date().toISOString().replace(/[:.]/g, '-') + '-telemetry-' + randomBytes(3).toString('hex');
const local = join(root, '.local-dev', runId), evidence = join(root, 'docs/implementation/evidence', runId);
const report = { runId, startedAt: new Date().toISOString(), status: 'FAIL', checks: [], binaries: {},
  scope: 'Fresh isolated native PostgreSQL + real Go HTTPS + actual Rust Linux and Windows processes; Docker Engine read-only',
  limitations: ['No real PVE endpoint/token; no PVE acceptance', 'No systemd/SCM installation, reboot, production load or external server', 'Host CPU/memory/disk/network subset only; not full PRD completion'] };
const sha = x => createHash('sha256').update(x).digest('hex');
const secrets = [];
function secret() { const s = randomBytes(32).toString('base64url'); secrets.push(s); return s; }
function redact(s) { for (const value of secrets) s = s.replaceAll(value, '[REDACTED]'); return s; }
function check(value, label) { report.checks.push({ label, status: value ? 'PASS' : 'FAIL' }); if (!value) throw Error(label); }
function run(command, args, { env = process.env, cwd = root, input, expect = 0, timeout = 180000 } = {}) {
  const result = spawnSync(command, args, { env, cwd, input, timeout, maxBuffer: 8 * 1024 * 1024 });
  if (result.error || result.status !== expect) throw Error(`${command.split('/').pop()} exited ${result.status}: ${redact(result.stderr?.toString() || result.error?.message || '')}`);
  return result.stdout.toString();
}
const delay = ms => new Promise(r => setTimeout(r, ms));
const docker = args => run('docker', args);
const image = 'postgres@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873';
const container = 'infrascope-' + runId.toLowerCase();
let created = false, app, env, ca, origin, cookie = '', csrf = '';
async function request(path, method = 'GET', data, expected = 200) {
  const bytes = data === undefined ? undefined : Buffer.from(JSON.stringify(data));
  const result = await new Promise((resolve, reject) => {
    const req = httpsRequest(origin + path, { method, ca, agent: false, headers: { Origin: origin, Cookie: cookie, 'X-CSRF-Token': csrf,
      ...(bytes ? { 'Content-Type': 'application/json', 'Content-Length': bytes.length } : {}) } }, res => {
      const chunks = []; res.on('data', c => chunks.push(c)); res.on('end', () => resolve({ code: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(10000, () => req.destroy(Error('HTTPS timeout'))); req.on('error', reject); req.end(bytes);
  });
  if (result.headers['set-cookie']) cookie = result.headers['set-cookie'].map(x => x.split(';')[0]).join('; ');
  let parsed; try { parsed = JSON.parse(result.body); } catch { throw Error('Invalid HTTPS JSON response'); }
  if (result.code !== expected) throw Error(`${method} ${path}: expected ${expected}, got ${result.code}: ${redact(result.body)}`);
  if (parsed.csrf) csrf = parsed.csrf;
  return parsed;
}
async function start() {
  const log = await open(join(local, 'server.log'), 'a', 0o600);
  app = spawn(join(local, 'server'), ['serve'], { cwd: root, env, stdio: ['ignore', log.fd, log.fd] }); await log.close();
  for (let i = 0; i < 100; i++) { try { await request('/api/remote-access/auth/me', 'GET', undefined, cookie ? 200 : 401); return; } catch {} await delay(100); }
  throw Error('isolated HTTPS server not ready');
}
async function stop() {
  if (!app || app.exitCode !== null) return;
  const child = app;
  const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGTERM');
  const timer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); }, 15000);
  await exited; clearTimeout(timer);
}
const sql = text => run('docker', ['exec', '-i', container, 'psql', '-X', '-U', 'postgres', '-d', 'telemetry_test', '-v', 'ON_ERROR_STOP=1', '-At'], { input: text }).trim();
async function client(kind, label, windows = false) {
  const name = kind === 'host' ? 'infrascope-agent' : `infrascope-${kind}-collector`;
  const linux = join(root, 'telemetry-agent/target/release', name);
  if (windows && !process.env.INFRASCOPE_WINDOWS_TEST_DIR) throw Error('Set INFRASCOPE_WINDOWS_TEST_DIR to a private Windows-mounted directory');
  const dir = windows ? join(process.env.INFRASCOPE_WINDOWS_TEST_DIR, runId) : join(local, label);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const binary = windows ? join(dir, name + '.exe') : linux;
  if (windows) await copyFile(join(root, 'telemetry-agent/target/x86_64-pc-windows-gnu/release', name + '.exe'), binary);
  report.binaries[label] = { sha256: sha(await readFile(binary)), platform: windows ? 'windows-x86_64-native' : 'linux-x86_64-native' };
  const asPath = p => windows ? run('wslpath', ['-w', p]).trim().replaceAll('\\', '/') : p;
  const config = join(dir, 'agent.toml'); await copyFile(join(root, '.local-dev/tls/server.crt'), join(dir, 'server.crt'));
  await writeFile(config, `server_url = ${JSON.stringify(origin)}\nstate_dir = ${JSON.stringify(asPath(join(dir, 'state')))}\nca_cert = ${JSON.stringify(asPath(join(dir, 'server.crt')))}\nrequest_timeout_seconds = 2\n` +
    (kind === 'docker' ? '[docker]\nendpoint = "unix:///var/run/docker.sock"\nmax_containers = 100\ntimeout_seconds = 10\n' : ''), { mode: 0o600 });
  const person = await request('/api/remote-access/people', 'POST', { displayName: `Telemetry test ${label}`, contactType: 'internal', enabled: true });
  const asset = await request('/api/v1/assets', 'POST', { name: `Telemetry real test ${label}`, category: kind === 'pve' ? 'pve' : 'server', kind: 'physical', osFamily: windows ? 'windows' : 'linux', enabled: true, endpoints: [], ownership: { state: 'pending', claimantId: person.id } });
  const enrollment = await request('/api/v1/agents/enrollments', 'POST', { assetId: asset.id, kind, expiresInSeconds: 600 }, 201); secrets.push(enrollment.token);
  const cli = (command, expect = 0, extra = {}) => run(binary, [command, '--config', asPath(config)], { expect, env: { ...process.env, ...extra,
    WSLENV: [process.env.WSLENV, 'INFRASCOPE_ENROLLMENT_TOKEN/w'].filter(Boolean).join(':') } });
  const enrolled = JSON.parse(cli('enroll', 0, { INFRASCOPE_ENROLLMENT_TOKEN: enrollment.token }));
  check(enrolled.enrolled && enrolled.assetId === asset.id, `${label}: actual binary HTTPS enrollment bound to asset`);
  const once = JSON.parse(cli('once')); check(once.acknowledgedBatches > 0 && once.pendingBatches === 0, `${label}: durable server ACK clears local queue`);
  const telemetry = await request(`/api/v1/assets/${asset.id}/telemetry`), sample = telemetry.samples[0];
  check(sample?.kind === kind && sample.health.status === 'ok', `${label}: authenticated API reads actual persisted healthy sample`);
  check(sql(`SELECT count(*) FROM ra_agent_samples WHERE agent_id='${enrolled.agentId}'`) === '1', `${label}: independent PostgreSQL row read confirms persistence`);
  if (kind === 'host') {
    check(BigInt(sample.metrics.memory.totalBytes) > 0n && sample.metrics.cpu.logicalCount > 0, `${label}: real OS CPU and memory, decimal counters`);
    check(sample.metrics.networkInterfaces.every(n => n.receivedBytesPerSecond === null && n.rateQuality === 'baseline_required'), `${label}: first network rate is unknown, not a fabricated zero`);
    check(sample.metrics.disks.length > 0, `${label}: real mounted disk capacity available`);
  } else check(sample.metrics.status === 'ok', `${label}: Docker real Engine collection complete`);
  return { cli, config, assetId: asset.id, agentId: enrolled.agentId, sample };
}

await mkdir(local, { recursive: true, mode: 0o700 }); await mkdir(evidence, { recursive: true });
try {
  run('go', ['build', '-o', join(local, 'server'), './cmd/infrascope'], { cwd: join(root, 'remote-access') });
  const password = secret();
  run('docker', ['run', '--detach', '--rm', '--name', container, '--label', `infrascope.telemetry.test=${runId}`, '--memory', '512m', '--cpus', '2', '--tmpfs', '/var/lib/postgresql:rw,nosuid,size=384m', '--publish', '127.0.0.1::5432', '--env', 'POSTGRES_PASSWORD', '--env', 'POSTGRES_DB=telemetry_test', image], { env: { ...process.env, POSTGRES_PASSWORD: password } }); created = true;
  for (let i = 0; i < 100; i++) { if (spawnSync('docker', ['exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], { stdio: 'ignore' }).status === 0) break; await delay(100); }
  const dbAddress = docker(['port', container, '5432/tcp']).trim(); check(/^127\.0\.0\.1:\d+$/.test(dbAddress), 'isolated PostgreSQL binds loopback');
  const port = await new Promise((resolve, reject) => { const s = createServer(); s.on('error', reject); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); }); });
  origin = `https://127.0.0.1:${port}`; ca = await readFile(join(root, '.local-dev/tls/server.crt'));
  env = { ...process.env, DATABASE_URL: `postgres://postgres:${password}@${dbAddress}/telemetry_test?sslmode=disable`, REMOTE_ENABLED: 'true', REMOTE_LOOPBACK_TEST: 'false',
    REMOTE_LISTEN: `127.0.0.1:${port}`, REMOTE_PUBLIC_ORIGIN: origin, REMOTE_TLS_CERT: join(root, '.local-dev/tls/server.crt'), REMOTE_TLS_KEY: join(root, '.local-dev/tls/server.key'),
    REMOTE_HTTP_REDIRECT_LISTEN: '', REMOTE_STATIC_DIR: join(root, 'dist'), REMOTE_WORKSPACE: runId, REMOTE_GATEWAY_ID: runId, REMOTE_ALLOWED_CIDRS: '', REMOTE_GATEWAY_PEERS: '{}',
    REMOTE_SECRET_KEYS: JSON.stringify({ test: randomBytes(32).toString('base64') }), REMOTE_ACTIVE_KEY_VERSION: 'test' };
  run(join(local, 'server'), ['migrate'], { env });
  check(sql('SELECT max(version) FROM ra_schema_versions') === '8', 'real PostgreSQL migration 008 installed');
  const admin = { username: 'telemetry-e2e', displayName: 'Telemetry isolated QA', password: secret() };
  run(join(local, 'server'), ['bootstrap'], { env, input: JSON.stringify(admin) }); await start();
  await request('/api/remote-access/auth/login', 'POST', { username: admin.username, password: admin.password });
  const host = await client('host', 'linux-host');
  await request(`/api/v1/agents/${host.agentId}/config`, 'PATCH', { version: 1, intervalSeconds: 2, enabled: true, collectors: ['host'] });
  const updated = JSON.parse(host.cli('once')); check(updated.configVersion === 2, 'Linux: new desired config applied locally');
  host.cli('once');
  check((await request(`/api/v1/agents?assetId=${host.assetId}`))[0].appliedVersion === 2, 'Linux: applied version acknowledged to database');
  const before = sql(`SELECT count(*) FROM ra_agent_samples WHERE agent_id='${host.agentId}'`);
  await request(`/api/v1/agents/${host.agentId}/config`, 'PATCH', { version: 2, intervalSeconds: 2, enabled: false, collectors: ['host'] });
  check(JSON.parse(host.cli('once')).enabled === false && sql(`SELECT count(*) FROM ra_agent_samples WHERE agent_id='${host.agentId}'`) === before, 'Remote disable stops new sampling without fabricated data');
  await request(`/api/v1/agents/${host.agentId}/config`, 'PATCH', { version: 3, intervalSeconds: 2, enabled: true, collectors: ['host'] }); host.cli('once');
  await stop(); host.cli('once', 1);
  check(JSON.parse(host.cli('status')).pendingBatches === 1, 'Offline HTTPS failure retains one durable queued batch');
  await start();
  const resumed = JSON.parse(host.cli('once')); check(resumed.acknowledgedBatches === 2 && resumed.pendingBatches === 0, 'Server restart: offline backlog and new sample committed then ACKed');
  await client('docker', 'linux-docker');
  await client('host', 'windows-host', true);
  await request(`/api/v1/agents/${host.agentId}/revoke`, 'POST', { confirm: true }); host.cli('once', 1);
  check(JSON.parse(host.cli('status')).pendingBatches === 1, 'Revocation rejects upload; no false ACK or data discard');
  report.status = 'PASS';
} catch (error) { report.error = redact(error.message); console.error(report.error); process.exitCode = 1; }
finally {
  await stop();
  if (created) { const owner = docker(['inspect', '--format', '{{index .Config.Labels "infrascope.telemetry.test"}}', container]).trim(); if (owner === runId) docker(['rm', '--force', container]); }
  report.finishedAt = new Date().toISOString();
  report.sourceSha256 = Object.fromEntries(await Promise.all(['scripts/test-telemetry-e2e.mjs', 'telemetry-agent/Cargo.lock', 'dist/remote-access.js', 'remote-access/internal/access/telemetry.go'].map(async path => [path, sha(await readFile(join(root, path)))])));
  await writeFile(join(evidence, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, checks: report.checks.length, evidence, error: report.error }));
}
