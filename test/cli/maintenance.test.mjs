// Hardening scenarios for the encrypted store, driven end-to-end with the real
// git CLI + git-remote-egit + proxy + MinIO:
//  - force-push / history rewrite semantics (and ref-only force-backs)
//  - pack compaction (--compact), reachability GC (--gc), orphan prune (--prune)
//  - ciphertext integrity: a tampered store object must fail loudly, never
//    yield wrong data
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, readFile, symlink, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, storeReachable, put, getBytes, list, del } from '../helpers/minio.mjs';
import { createProxy } from '../../src/gateway/proxy.js';
import { isEncrypted } from '../../src/core/crypto.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const client = makeClient();
const reachable = await storeReachable(client);
if (reachable) await ensureBucket(client);
else console.warn('\n[skip] object store not reachable — start MinIO or set S3_ENDPOINT.\n');

const KEY_HEX = 'f'.repeat(64);
const repoId = `maint-${Date.now()}`;

let server, proxyUrl, work, env;

const noise = (len, seed = 1) => {
    const out = Buffer.alloc(len);
    let s = seed >>> 0 || 1;
    for (let i = 0; i < len; i++) {
        s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
        out[i] = s & 0xff;
    }
    return out;
};

before(async () => {
    if (!reachable) return;
    const app = createProxy();
    server = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
    proxyUrl = `http://127.0.0.1:${server.address().port}`;

    work = await mkdtemp(join(tmpdir(), 'egit-maint-'));
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
    server?.close();
    if (work) await rm(work, { recursive: true, force: true });
    if (reachable) for (const k of await list(client, `${repoId}/`)) await del(client, k).catch(() => {});
});

const git = (cwd, ...args) => execFileP('git', args, { cwd, env });
const egit = (...args) => execFileP('git-remote-egit', args, { env });
const remoteUrl = () => `egit::${proxyUrl}/${repoId}`;
const storeUrl = () => `${proxyUrl}/${repoId}`;
const packKeys = async () => (await list(client, `${repoId}/packs/`))
    .map(k => Number(k.slice(`${repoId}/packs/`.length))).sort((a, b) => a - b);

describe('force-push / history rewrite', () => {
    test('force push rewrites history; fresh clones follow the rewrite', { skip: !reachable }, async () => {
        const a = join(work, 'a');
        await mkdir(a);
        await git(a, 'init', '-b', 'main');
        await writeFile(join(a, 'keep.txt'), 'kept\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'base');
        await writeFile(join(a, 'oops.txt'), 'to be rewritten away\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'oops');
        await git(a, 'push', remoteUrl(), 'main');

        // Rewrite: drop "oops", commit something else instead.
        await git(a, 'reset', '--hard', 'HEAD~1');
        await writeFile(join(a, 'better.txt'), 'the fixed version\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'better');

        // Non-forced push of the rewrite must be rejected…
        await assert.rejects(() => git(a, 'push', remoteUrl(), 'main'),
            /non-fast-forward|rejected|fetch first/i);
        // …the forced one goes through.
        await git(a, 'push', '--force', remoteUrl(), 'main');

        const b = join(work, 'b');
        await git(work, 'clone', remoteUrl(), b);
        const { stdout: log } = await git(b, 'log', '--format=%s');
        assert.deepEqual(log.trim().split('\n'), ['better', 'base']);
        await assert.rejects(() => readFile(join(b, 'oops.txt')), 'rewritten-away file must not exist');
        await git(b, 'fsck', '--strict');
    });

    test('stale non-force push AFTER someone else force-pushed → fetch first', { skip: !reachable }, async () => {
        // b clones, a force-pushes something b has never seen, b pushes → must fail.
        const a = join(work, 'a');
        const b = join(work, 'b');
        await git(a, 'commit', '--allow-empty', '-m', 'a moves ahead');
        await git(a, 'push', '--force', remoteUrl(), 'main');

        await writeFile(join(b, 'b.txt'), 'b\n');
        await git(b, 'add', '.');
        await git(b, 'commit', '-m', 'b diverges');
        await assert.rejects(() => git(b, 'push', remoteUrl(), 'main'),
            /non-fast-forward|rejected|fetch first/i);
        await git(b, 'pull', '--rebase', remoteUrl(), 'main');
        await git(b, 'push', remoteUrl(), 'main');
    });

    test('force push back to an ancestor is a ref-only update (no new pack)', { skip: !reachable }, async () => {
        const b = join(work, 'b');
        const before = await packKeys();
        await git(b, 'reset', '--hard', 'HEAD~1');
        await git(b, 'push', '--force', remoteUrl(), 'main');
        assert.deepEqual(await packKeys(), before, 'no pack added for a ref-only move');

        const c = join(work, 'c-refonly');
        await git(work, 'clone', remoteUrl(), c);
        const { stdout: shaB } = await git(b, 'rev-parse', 'main');
        const { stdout: shaC } = await git(c, 'rev-parse', 'main');
        assert.equal(shaC, shaB);
    });

    test('new branch at an existing commit stores no new pack', { skip: !reachable }, async () => {
        const b = join(work, 'b');
        const before = await packKeys();
        await git(b, 'push', remoteUrl(), 'main:refs/heads/copy');
        assert.deepEqual(await packKeys(), before);
        const { stdout: refs } = await git(b, 'ls-remote', remoteUrl());
        assert.match(refs, /refs\/heads\/copy/);
    });
});

describe('maintenance: compact / gc / prune', () => {
    test('--compact merges N packs into 1; clones and refs are unaffected', { skip: !reachable }, async () => {
        const before = await packKeys();
        assert.ok(before.length > 1, `needs multiple packs to be meaningful (have ${before.length})`);
        const { stdout: refsBefore } = await git(work, 'ls-remote', remoteUrl());

        await egit('--compact', storeUrl());

        const after = await packKeys();
        assert.equal(after.length, 1, 'one pack after compaction');
        assert.ok(after[0] > Math.max(...before), 'compacted pack gets a fresh index');
        assert.ok(isEncrypted(await getBytes(client, `${repoId}/packs/${after[0]}`)));

        const { stdout: refsAfter } = await git(work, 'ls-remote', remoteUrl());
        assert.equal(refsAfter, refsBefore, 'refs identical across compaction');

        const c = join(work, 'c-compacted');
        await git(work, 'clone', remoteUrl(), c);
        await git(c, 'fsck', '--strict');
        assert.equal(await readFile(join(c, 'keep.txt'), 'utf8'), 'kept\n');
    });

    test('--gc drops objects orphaned by force-pushes and shrinks the store', { skip: !reachable }, async () => {
        // Bury a 2MB binary in history, then rewrite it away → unreachable.
        const b = join(work, 'b');
        await git(b, 'pull', '--rebase', remoteUrl(), 'main');
        await writeFile(join(b, 'huge.bin'), noise(2 * 1024 * 1024, 99));
        await git(b, 'add', '.');
        await git(b, 'commit', '-m', 'huge binary');
        await git(b, 'push', remoteUrl(), 'main');
        await git(b, 'reset', '--hard', 'HEAD~1');
        await git(b, 'push', '--force', remoteUrl(), 'main');

        const sizeOf = async () => {
            let total = 0;
            for (const n of await packKeys()) total += (await getBytes(client, `${repoId}/packs/${n}`)).length;
            return total;
        };
        // compact keeps the unreachable 2MB (no reachability knowledge)…
        await egit('--compact', storeUrl());
        assert.ok(await sizeOf() > 2 * 1024 * 1024, 'compaction alone cannot drop unreachable objects');
        // …gc drops it.
        await egit('--gc', storeUrl());
        assert.ok(await sizeOf() < 1024 * 1024, `gc should shrink well below the binary size, got ${await sizeOf()}`);
        assert.equal((await packKeys()).length, 1);

        const c = join(work, 'c-gc');
        await git(work, 'clone', remoteUrl(), c);
        await git(c, 'fsck', '--strict');
        assert.equal(await readFile(join(c, 'keep.txt'), 'utf8'), 'kept\n');
        await assert.rejects(() => readFile(join(c, 'huge.bin')), 'gc-ed content is gone');
        const { stdout: refs } = await git(work, 'ls-remote', remoteUrl());
        assert.match(refs, /refs\/heads\/copy/, 'all branches survive gc');
    });

    test('--prune removes orphaned packs but never referenced ones', { skip: !reachable }, async () => {
        // Simulate a lost-CAS leftover: an unreferenced pack object in the store.
        const referenced = await packKeys();
        const orphanN = Math.max(...referenced) + 17;
        await put(client, `${repoId}/packs/${orphanN}`, Buffer.from('orphaned ciphertext leftovers'));
        assert.deepEqual(await packKeys(), [...referenced, orphanN].sort((a, b) => a - b));

        // Age guard: a young orphan survives an hour-threshold prune…
        await egit('--prune', storeUrl());
        assert.ok((await packKeys()).includes(orphanN), 'fresh orphan must survive the default age guard');
        // …and is swept with the guard at 0.
        await egit('--prune=0', storeUrl());
        assert.deepEqual(await packKeys(), referenced, 'orphan gone, referenced packs untouched');

        const { stdout: refs } = await git(work, 'ls-remote', remoteUrl());
        assert.match(refs, /refs\/heads\/main/);
    });
});

describe('ciphertext integrity (GCM)', () => {
    test('a tampered pack fails decryption on clone — never yields wrong data', { skip: !reachable }, async () => {
        const [n] = await packKeys();
        const key = `${repoId}/packs/${n}`;
        const original = await getBytes(client, key);
        const tampered = Buffer.from(original);
        tampered[tampered.length - 1] ^= 0xff; // flip one ciphertext byte
        await put(client, key, tampered);

        await assert.rejects(
            () => git(work, 'clone', remoteUrl(), join(work, 'c-tampered')),
            'clone from a tampered store must fail');

        await put(client, key, original); // restore
        await git(work, 'clone', remoteUrl(), join(work, 'c-restored'));
    });

    test('a tampered refs manifest fails on ls-remote', { skip: !reachable }, async () => {
        const key = `${repoId}/refs`;
        const original = await getBytes(client, key);
        const tampered = Buffer.from(original);
        tampered[10] ^= 0xff;
        await put(client, key, tampered);

        await assert.rejects(() => git(work, 'ls-remote', remoteUrl()));

        await put(client, key, original);
        const { stdout: refs } = await git(work, 'ls-remote', remoteUrl());
        assert.match(refs, /refs\/heads\/main/);
    });
});
