import { readFile, writeFile } from 'node:fs/promises';

// wasm-pack generates name/version from tcx-wasm/Cargo.toml; never duplicate them here.
const [source, destination] = process.argv.slice(2);
const manifest = JSON.parse(await readFile(source, 'utf8'));
manifest.files = [...new Set([...manifest.files, 'tcx_wasm_bg.wasm.d.ts'])];
manifest.type = 'module';
manifest.exports = {
  '.': { types: './tcx_wasm.d.ts', import: './tcx_wasm.js' },
  './tcx_wasm_bg.wasm': './tcx_wasm_bg.wasm',
};
await writeFile(destination, `${JSON.stringify(manifest, null, 2)}\n`);
