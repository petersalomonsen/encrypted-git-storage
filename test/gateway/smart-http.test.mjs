// Drives the service worker's smart-HTTP protocol logic (core/smart-http.js via
// the node adapter in helpers/smart-server.mjs) with the REAL git CLI — including
// cross-transport interop with the remote helper on the same encrypted store:
//
//   git ──smart HTTP──> core/smart-http (SW logic) ─┐
//   git ──remote-helper protocol──> git-remote-egit ─┴─> proxy ──> MinIO (ciphertext)
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, storeReachable, getBytes, list, del } from '../helpers/minio.mjs';
import { createProxy } from '../../src/gateway/proxy.js';
import { createSmartServer } from '../helpers/smart-server.mjs';
import { isEncrypted } from '../../src/core/crypto.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const client = makeClient();
const reachable = await storeReachable(client);
if (reachable) await ensureBucket(client);
else console.warn('\n[skip] object store not reachable — start MinIO or set S3_ENDPOINT.\n');

const KEY_HEX = 'c'.repeat(64);
const KEY = Uint8Array.from(KEY_HEX.match(/../g), h => parseInt(h, 16));
const repoId = `smart-http-${Date.now()}`;

let proxy, smart, smartUrl, work, env;

before(async () => {
    if (!reachable) return;
    const app = createProxy();
    proxy = await new Promise(res => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
    const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
    smart = createSmartServer({ proxyUrl, key: KEY });
    await new Promise(res => smart.listen(0, '127.0.0.1', res));
    smartUrl = `http://127.0.0.1:${smart.address().port}/git/${repoId}`;

    work = await mkdtemp(join(tmpdir(), 'egit-smart-'));
    const bin = join(work, 'bin');
    await mkdir(bin);
    await chmod(HELPER, 0o755);
    await symlink(HELPER, join(bin, 'git-remote-egit'));
    env = {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        EGIT_KEY: KEY_HEX,
        GIT_AUTHOR_NAME: 'Test', GIT_AUTHOR_EMAIL: 'test@example.com',
        GIT_COMMITTER_NAME: 'Test', GIT_COMMITTER_EMAIL: 'test@example.com',
    };
});

after(async () => {
    proxy?.close();
    smart?.close();
    if (work) await rm(work, { recursive: true, force: true });
    if (reachable) for (const k of await list(client, `${repoId}/`)) await del(client, k).catch(() => {});
});

const git = (cwd, ...args) => execFileP('git', args, { cwd, env });
const helperUrl = () => `egit::http://127.0.0.1:${proxy.address().port}/${repoId}`;

describe('smart HTTP (the service-worker protocol) driven by the real git CLI', () => {
    test('clone empty → commit → push over smart HTTP', { skip: !reachable }, async () => {
        const a = join(work, 'a');
        await git(work, 'clone', smartUrl, a);
        await git(a, 'checkout', '-b', 'main');
        await writeFile(join(a, 'hello.txt'), 'served by core/smart-http\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'first over http');
        await git(a, 'push', 'origin', 'main');

        const keys = await list(client, `${repoId}/`);
        assert.ok(keys.includes(`${repoId}/refs`));
        for (const k of keys) assert.ok(isEncrypted(await getBytes(client, k)), `${k} is ciphertext`);
    });

    test('clone over smart HTTP returns the pushed content', { skip: !reachable }, async () => {
        const b = join(work, 'b');
        await git(work, 'clone', smartUrl, b);
        assert.equal(await readFile(join(b, 'hello.txt'), 'utf8'), 'served by core/smart-http\n');
        const { stdout: branch } = await git(b, 'rev-parse', '--abbrev-ref', 'HEAD');
        assert.equal(branch.trim(), 'main', 'HEAD symref advertised main');
    });

    test('incremental push + fetch over smart HTTP (merged multi-pack upload)', { skip: !reachable }, async () => {
        const a = join(work, 'a');
        for (let i = 0; i < 3; i++) {
            await writeFile(join(a, `file-${i}.txt`), `content ${i}\n`.repeat(1000));
            await git(a, 'add', '.');
            await git(a, 'commit', '-m', `commit ${i}`);
            await git(a, 'push', 'origin', 'main');
        }
        // 4 pushes so far → 4 packs; upload-pack must merge them into one.
        const packs = await list(client, `${repoId}/packs/`);
        assert.equal(packs.length, 4);

        const b = join(work, 'b');
        await git(b, 'pull', 'origin', 'main');           // incremental fetch
        assert.equal(await readFile(join(b, 'file-2.txt'), 'utf8'), 'content 2\n'.repeat(1000));

        const c = join(work, 'c');
        await git(work, 'clone', smartUrl, c);            // cold clone replays everything
        await git(c, 'fsck', '--strict');
        const { stdout: log } = await git(c, 'log', '--format=%s');
        assert.equal(log.trim().split('\n').length, 4);
    });

    test('stale push over smart HTTP is rejected (old-sha check)', { skip: !reachable }, async () => {
        const b = join(work, 'b');
        // b is stale relative to a's last pushes? No — b pulled. Make b and a diverge:
        const a = join(work, 'a');
        await writeFile(join(a, 'a-side.txt'), 'a\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'a-side');
        await git(a, 'push', 'origin', 'main');

        await writeFile(join(b, 'b-side.txt'), 'b\n');
        await git(b, 'add', '.');
        await git(b, 'commit', '-m', 'b-side');
        await assert.rejects(
            () => git(b, 'push', 'origin', 'main'),
            /rejected|fetch first|non-fast-forward/i);

        await git(b, 'pull', '--rebase', 'origin', 'main');
        await git(b, 'push', 'origin', 'main');
    });

    test('interop: remote-helper push ↔ smart-HTTP clone (and back)', { skip: !reachable }, async () => {
        // Push via the egit:: remote helper…
        const d = join(work, 'd');
        await git(work, 'clone', helperUrl(), d);
        await writeFile(join(d, 'via-helper.txt'), 'pushed through git-remote-egit\n');
        await git(d, 'add', '.');
        await git(d, 'commit', '-m', 'via helper');
        await git(d, 'push', 'origin', 'main');

        // …and read it back over smart HTTP (the SW's view of the same store).
        const e = join(work, 'e');
        await git(work, 'clone', smartUrl, e);
        assert.equal(await readFile(join(e, 'via-helper.txt'), 'utf8'), 'pushed through git-remote-egit\n');

        // Then push over smart HTTP and read back through the helper.
        await writeFile(join(e, 'via-http.txt'), 'pushed through smart HTTP\n');
        await git(e, 'add', '.');
        await git(e, 'commit', '-m', 'via http');
        await git(e, 'push', 'origin', 'main');

        const f = join(work, 'f');
        await git(work, 'clone', helperUrl(), f);
        assert.equal(await readFile(join(f, 'via-http.txt'), 'utf8'), 'pushed through smart HTTP\n');
        await git(f, 'fsck', '--strict');
    });

    test('force push over smart HTTP rewrites history; ref-only force-back adds no pack', { skip: !reachable }, async () => {
        const a = join(work, 'a');
        await git(a, 'pull', '--rebase', 'origin', 'main'); // catch up with earlier tests' pushes
        await writeFile(join(a, 'mistake.txt'), 'rewrite me\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'mistake');
        await git(a, 'push', 'origin', 'main');

        await git(a, 'reset', '--hard', 'HEAD~1');
        await git(a, 'commit', '--allow-empty', '-m', 'fixed');
        await assert.rejects(() => git(a, 'push', 'origin', 'main'), /non-fast-forward|rejected|fetch first/i);
        await git(a, 'push', '--force', 'origin', 'main');

        const g = join(work, 'g');
        await git(work, 'clone', smartUrl, g);
        const { stdout: log } = await git(g, 'log', '--format=%s', '-2');
        assert.deepEqual(log.trim().split('\n')[0], 'fixed');
        await assert.rejects(() => readFile(join(g, 'mistake.txt')));
        await git(g, 'fsck', '--strict');

        // Force back to the parent: pure ref move, receive-pack must store no pack.
        const packsBefore = (await list(client, `${repoId}/packs/`)).length;
        await git(a, 'reset', '--hard', 'HEAD~1');
        await git(a, 'push', '--force', 'origin', 'main');
        assert.equal((await list(client, `${repoId}/packs/`)).length, packsBefore, 'ref-only force adds no pack');
    });

    test('branch deletion over smart HTTP', { skip: !reachable }, async () => {
        const a = join(work, 'a');
        await git(a, 'checkout', '-b', 'temp');
        await git(a, 'push', 'origin', 'temp');
        let { stdout: refs } = await git(a, 'ls-remote', 'origin');
        assert.match(refs, /refs\/heads\/temp/);

        await git(a, 'push', 'origin', ':temp');
        ({ stdout: refs } = await git(a, 'ls-remote', 'origin'));
        assert.doesNotMatch(refs, /refs\/heads\/temp/);
        await git(a, 'checkout', 'main');
    });
});
