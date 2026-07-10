// Proves the repo is consumable as a package:
//  - `npm pack` (runs `prepare` → esbuild) produces a tarball whose `files`
//    include src/, the bin, and the bundled dist/sw.js
//  - a consumer project can `import { createProxy } from 'encrypted-git-storage/gateway'`
//    and `import { encrypt, … } from 'encrypted-git-storage/core'` through the
//    exports map, and actually run the gateway
//
// The tarball is extracted into <tmp>/node_modules/encrypted-git-storage and the
// package's two runtime deps are symlinked from this repo's node_modules (node
// resolves through the realpath, so their own transitive deps keep working) —
// full fidelity to a real install, without hitting the npm registry.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, symlink, rm, access, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileP = promisify(execFile);
const ROOT = resolve(fileURLToPath(import.meta.url), '../../..');

let work, pkgDir;

before(async () => {
    work = await mkdtemp(join(tmpdir(), 'egit-consumer-'));
    const { stdout } = await execFileP('npm', ['pack', '--pack-destination', work], { cwd: ROOT });
    const tarball = join(work, stdout.trim().split('\n').pop());

    const nm = join(work, 'node_modules');
    pkgDir = join(nm, 'encrypted-git-storage');
    await mkdir(pkgDir, { recursive: true });
    await execFileP('tar', ['-xzf', tarball, '--strip-components=1', '-C', pkgDir]);
    for (const dep of ['express', '@aws-sdk']) {
        await symlink(join(ROOT, 'node_modules', dep), join(nm, dep));
    }
    await writeFile(join(work, 'package.json'), JSON.stringify({ type: 'module' }));
});

after(() => rm(work, { recursive: true, force: true }));

describe('consumable as a package', () => {
    test('tarball ships src, the bin, and the bundled dist/sw.js (via prepare)', async () => {
        for (const f of [
            'package.json',
            'src/core/index.js',
            'src/gateway/proxy.js',
            'src/remote-helper/git-remote-egit.js',
            'dist/sw.js',
        ]) await access(join(pkgDir, f));

        // The SW bundle must be self-contained: no imports left to resolve.
        const sw = await readFile(join(pkgDir, 'dist/sw.js'), 'utf8');
        assert.ok(!/\bfrom\s+['"]/.test(sw), 'dist/sw.js has no external imports');
        assert.match(sw, /egit-set-key/, 'bundle contains the SW logic');
    });

    test("consumer can `import 'encrypted-git-storage/gateway'` and run the proxy", async () => {
        await writeFile(join(work, 'consume.mjs'), `
            import { createProxy } from 'encrypted-git-storage/gateway';
            import { encrypt, decrypt, isEncrypted, emptyManifest, makeStoreClient }
                from 'encrypted-git-storage/core';
            import { compact } from 'encrypted-git-storage'; // "." → core too

            // core works…
            const key = crypto.getRandomValues(new Uint8Array(32));
            const blob = await encrypt(key, new TextEncoder().encode('hi'));
            if (!isEncrypted(blob)) throw new Error('isEncrypted');
            if (new TextDecoder().decode(await decrypt(key, blob)) !== 'hi') throw new Error('roundtrip');
            if (emptyManifest().generation !== 0) throw new Error('manifest');
            void makeStoreClient; void compact;

            // …and the gateway boots and enforces its auth stub.
            const server = createProxy().listen(0, '127.0.0.1', async () => {
                const res = await fetch(\`http://127.0.0.1:\${server.address().port}/some-repo/refs\`);
                console.log(res.status === 401 ? 'CONSUMER-OK' : 'CONSUMER-BAD:' + res.status);
                server.close();
            });
        `);
        const { stdout } = await execFileP('node', ['consume.mjs'], { cwd: work });
        assert.equal(stdout.trim(), 'CONSUMER-OK');
    });
});
