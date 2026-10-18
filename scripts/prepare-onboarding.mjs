import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, copyFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('../', import.meta.url));
export async function prepareOnboarding(options = {}) {
  const out = join(options.staticRoot || join(root, 'dist'), 'downloads');
  await mkdir(out, { recursive: true });
  const archive = 'infrascope-telemetry-0.1.0-linux-x86_64-gnu.tar.gz';
  const manifest = { version: '0.1.0', linux: false, ca: false };
  try {
    const source = join(root, 'release', 'telemetry-0.1.0', archive);
    const bytes = await readFile(source);
    // The package is a public release artifact. Never copy local state or private keys.
    await copyFile(source, join(out, archive));
    manifest.linux = true;
    manifest.sha256 = createHash('sha256').update(bytes).digest('hex');
    manifest.bytes = (await stat(source)).size;
  } catch (e) { if (e.code !== 'ENOENT') throw e; }
  try {
    const cert = await readFile(options.certificate || join(root, '.local-dev', 'tls', 'server.crt'), 'utf8');
    if (!cert.includes('-----BEGIN CERTIFICATE-----') || cert.includes('PRIVATE KEY')) throw Error('Expected only public TLS certificate');
    await writeFile(join(out, 'server-ca.pem'), cert);
    manifest.ca = true;
  } catch (e) { if (e.code !== 'ENOENT') throw e; }
  await writeFile(join(out, 'onboarding.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log('Onboarding public downloads prepared:', JSON.stringify(manifest));
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const compose = process.argv.includes('--compose');
  if (compose) await readFile(join(root, '.runtime', 'compose.env'));
  await prepareOnboarding(compose ? { staticRoot: join(root, '.runtime'), certificate: join(root, '.runtime', 'tls', 'server.crt') } : {});
}
