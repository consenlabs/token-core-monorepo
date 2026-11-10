import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';

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
  const sourceManifest = JSON.parse(await readFile(join(root, 'publish/npm/package.json'), 'utf8'));
  const aggregate = sourceManifest.name === '@imtoken/wallet-core-web';
  assert.equal(packed.name, aggregate ? sourceManifest.name : metadata.name);
  assert.equal(packed.version, aggregate ? sourceManifest.version : metadata.version);
  const files = new Set(packed.files.map((file) => file.path));
  for (const file of ['package.json', 'README.md', 'tcx_wasm.js', 'tcx_wasm.d.ts', 'tcx_wasm_bg.wasm', 'tcx_wasm_bg.wasm.d.ts']) {
    assert(files.has(file), `missing packed file: ${file}`);
  }
  if (aggregate) {
    for (const file of ['index.js', 'index.d.ts', 'ikc_wasm.js', 'ikc_wasm_bg.wasm', 'imkey-session.js']) {
      assert(files.has(file), `missing aggregate package file: ${file}`);
    }
  }
  const consumer = join(directory, 'node_modules', packed.name);
  await mkdir(consumer, { recursive: true });
  execFileSync('tar', ['-xzf', join(directory, packed.filename), '--strip-components=1', '-C', consumer]);
  const manifest = JSON.parse(await readFile(join(consumer, 'package.json'), 'utf8'));
  assert.equal(manifest.type, 'module');
  if (aggregate) {
    const readme = await readFile(join(consumer, 'README.md'), 'utf8');
    assert(readme.startsWith(`# ${packed.name}\n`), 'package README must describe the aggregate SDK');
  }
  // Resolve by package name, exercising exports from the actual unpacked npm tarball.
  const output = execFileSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { readFile } from 'node:fs/promises';
    const entry = await import(${JSON.stringify(packed.name)});
    if (${aggregate}) {
      assert.equal(typeof entry.initTokenCore, 'function');
      assert.equal(typeof entry.createImKeyCore, 'function');
    }
    const api = ${aggregate} ? await import(${JSON.stringify(pathToFileURL(join(consumer, 'tcx_wasm.js')).href)}) : entry;
    const wasm = await readFile(${JSON.stringify(join(consumer, 'tcx_wasm_bg.wasm'))});
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
