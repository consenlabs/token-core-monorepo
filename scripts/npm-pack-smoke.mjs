import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const directory = await mkdtemp(join(tmpdir(), 'tcx-npm-smoke-'));
try {
  const [packed] = JSON.parse(execFileSync('npm', [
    'pack', '--json', '--offline', '--ignore-scripts', '--cache', join(directory, 'cache'),
    '--pack-destination', directory,
  ], { cwd: join(root, 'publish/npm'), encoding: 'utf8' }));
  const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--offline', '--no-deps', '--format-version', '1'], {
    cwd: root, encoding: 'utf8',
  })).packages.find((pkg) => pkg.name === 'tcx-wasm');
  assert.equal(packed.name, metadata.name);
  assert.equal(packed.version, metadata.version);
  const files = new Set(packed.files.map((file) => file.path));
  for (const file of ['package.json', 'tcx_wasm.js', 'tcx_wasm.d.ts', 'tcx_wasm_bg.wasm', 'tcx_wasm_bg.wasm.d.ts']) {
    assert(files.has(file), `missing packed file: ${file}`);
  }
  const consumer = join(directory, 'node_modules', packed.name);
  await mkdir(consumer, { recursive: true });
  execFileSync('tar', ['-xzf', join(directory, packed.filename), '--strip-components=1', '-C', consumer]);
  const manifest = JSON.parse(await readFile(join(consumer, 'package.json'), 'utf8'));
  assert.equal(manifest.type, 'module');
  // Resolve by package name, exercising exports from the actual unpacked npm tarball.
  const output = execFileSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { readFile } from 'node:fs/promises';
    const api = await import(${JSON.stringify(packed.name)});
    const wasm = await readFile(new URL(import.meta.resolve(${JSON.stringify(`${packed.name}/tcx_wasm_bg.wasm`)})));
    await api.default({ module_or_path: wasm });
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const prfKey = '07'.repeat(32);
    const keystoreJson = api.create_keystore(JSON.stringify({
      mnemonic, prfKey, userId: 'smoke', credentialId: 'smoke', rpId: 'localhost',
    }));
    assert.equal(JSON.parse(keystoreJson).version, 2);
    assert.equal(JSON.parse(api.export_mnemonic(JSON.stringify({ keystoreJson, prfKey }))).mnemonic, mnemonic);
    assert.equal(api.migrate_keystore(JSON.stringify({ keystoreJson, prfKey })), keystoreJson);
    console.log('npm tarball import + WASM create/export/migrate: passed');
  `], { cwd: directory, encoding: 'utf8' });
  process.stdout.write(output);
  console.log(`npm pack smoke: ${packed.name}@${packed.version} (${packed.files.length} files)`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
