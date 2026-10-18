import { spawnSync } from 'node:child_process';
import { cp, mkdir, access, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
const mode = process.argv[2] || 'service';
if (!['web', 'service', 'all'].includes(mode)) throw Error('Usage: node scripts/build.mjs web|service|all');
function run(command, args, cwd = root, env = process.env) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit', env });
  if (result.error || result.status !== 0) throw Error(`${command} failed: ${result.error?.message || result.status}`);
}
await access(join(root, 'node_modules', '@xterm', 'xterm', 'package.json')).catch(() => { throw Error('Run npm ci --ignore-scripts before building'); });
await mkdir(join(root, 'dist'), { recursive: true });
await cp(join(root, 'web'), join(root, 'dist'), { recursive: true });
run(process.execPath, ['scripts/vendor-terminal.mjs']);
console.log('Frontend built from web/ into dist/');
if (mode !== 'web') {
  const out = join(root, 'build', 'service');
  await mkdir(out, { recursive: true });
  run('go', ['build', '-trimpath', '-o', join(out, process.platform === 'win32' ? 'infrascope.exe' : 'infrascope'), './cmd/infrascope'], join(root, 'remote-access'), { ...process.env, CGO_ENABLED: '0' });
  await cp(join(root, 'dist'), join(out, 'web'), { recursive: true, filter: source => !source.startsWith(join(root, 'dist', 'downloads')) });
  await cp(join(root, 'remote-access', '.env.example'), join(out, 'remote-access.env.example'));
  await cp(join(root, 'docs', 'development', 'BUILD-AND-RUN.md'), join(out, 'BUILD-AND-RUN.md'));
  await writeFile(join(out, 'BUILD.json'), JSON.stringify({ version: '0.7.0', platform: process.platform, arch: process.arch, source: 'remote-access/', frontendSource: 'web/', secretsIncluded: false }, null, 2) + '\n');
  console.log('Service bundle: build/service/ (binary + web + example configuration)');
}
if (mode === 'all') {
  run('cargo', ['build', '--manifest-path', 'telemetry-agent/Cargo.toml', '--release', '--locked']);
  console.log('Telemetry clients built in telemetry-agent/target/release/');
}
