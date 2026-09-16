/*
 * Copies the shared detector, link layer and block page into each browser's extension folder
 * and writes the result to dist/. The shared files are the single source of truth; the copies
 * under dist/ are build output and are never edited by hand.
 *
 *   node scripts/build-extensions.mjs [--zip]
 */
import { cp, mkdir, rm, readdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

const SHARED = ['guard-detect.js', 'guard-link.js', 'blocked.html', 'blocked.css', 'blocked.js'];

const TARGETS = [
  { name: 'chromium', source: 'src/Guard.Chromium' },
  { name: 'firefox', source: 'src/Guard.Firefox' }
];

const shouldZip = process.argv.includes('--zip');

async function build(target) {
  const outDir = path.join(root, 'dist', target.name);
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  for (const file of SHARED) {
    await cp(path.join(root, 'src/extension-shared', file), path.join(outDir, file));
  }

  const sourceDir = path.join(root, target.source);
  for (const entry of await readdir(sourceDir)) {
    await cp(path.join(sourceDir, entry), path.join(outDir, entry), { recursive: true });
  }

  // A stamp makes it obvious which build a browser is actually running when debugging.
  await writeFile(
    path.join(outDir, 'BUILD.txt'),
    `Guard ${target.name} extension\nbuilt ${new Date().toISOString()}\n`
  );

  console.log(`built dist/${target.name}`);

  if (shouldZip) {
    const zipPath = path.join(root, 'dist', `guard-${target.name}.zip`);
    await rm(zipPath, { force: true });
    await run('zip', ['-r', '-q', zipPath, '.'], { cwd: outDir });
    console.log(`packed dist/guard-${target.name}.zip`);
  }
}

for (const target of TARGETS) {
  if (!existsSync(path.join(root, target.source))) {
    console.warn(`skipping ${target.name}: ${target.source} is missing`);
    continue;
  }
  await build(target);
}
