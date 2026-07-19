// Remote-helper scenario: real `git` + git-remote-egit + the gateway proxy + MinIO.
//
//   git ──remote-helper protocol──> git-remote-egit ──HTTP──> proxy ──S3──> MinIO
//
// The store only ever sees ciphertext; the AES key lives in EGIT_KEY on the client.
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
import { isEncrypted } from '../../src/core/crypto.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const client = makeClient();
const reachable = await storeReachable(client);
if (reachable) await ensureBucket(client);
else console.warn('\n[skip] object store not reachable — start MinIO or set S3_ENDPOINT.\n');

let server, proxyUrl, work, env;
const repoId = `cli-test-${Date.now()}`;
const KEY_HEX = 'a'.repeat(64); // deterministic 32-byte test key

before(async () => {
    if (!reachable) return;
    // Gateway proxy on an ephemeral port, backed by the MinIO test bucket.
    const app = createProxy();
    server = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
    proxyUrl = `http://127.0.0.1:${server.address().port}`;

    // Put git-remote-egit on PATH under the name git expects.
    work = await mkdtemp(join(tmpdir(), 'egit-cli-'));
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
const remoteUrl = () => `egit::${proxyUrl}/${repoId}`;

describe('remote-helper (git-remote-egit) over encrypted object store', () => {
    test('push → clone round-trips via git CLI', { skip: !reachable }, async () => {
        const a = join(work, 'repo-a');
        await mkdir(a);
        await git(a, 'init', '-b', 'main');
        await writeFile(join(a, 'hello.txt'), 'hello encrypted world\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'first commit');
        await git(a, 'push', remoteUrl(), 'main');

        const b = join(work, 'repo-b');
        await git(work, 'clone', remoteUrl(), b);
        assert.equal(await readFile(join(b, 'hello.txt'), 'utf8'), 'hello encrypted world\n');

        const { stdout: shaA } = await git(a, 'rev-parse', 'main');
        const { stdout: shaB } = await git(b, 'rev-parse', 'main');
        assert.equal(shaB, shaA, 'clone has the same tip commit');
    });

    test('stored packs and refs are ciphertext (zero-knowledge)', { skip: !reachable }, async () => {
        const keys = await list(client, `${repoId}/`);
        assert.ok(keys.includes(`${repoId}/refs`), 'refs manifest stored');
        assert.ok(keys.some(k => k.startsWith(`${repoId}/packs/`)), 'at least one pack stored');

        for (const key of keys) {
            const bytes = await getBytes(client, key);
            assert.ok(isEncrypted(bytes), `${key} carries the EGS1 encrypted framing`);
            // Zero-knowledge: no plaintext git pack, no readable refs JSON.
            assert.notDeepEqual(bytes.subarray(4, 8), Buffer.from('PACK'));
            assert.equal(bytes.includes(Buffer.from('PACK')), false, `${key} has no plaintext PACK header`);
            assert.equal(bytes.includes(Buffer.from('refs/heads')), false, `${key} leaks no ref names`);
        }
    });

    test('incremental push → second clone gets both commits', { skip: !reachable }, async () => {
        const a = join(work, 'repo-a');
        await writeFile(join(a, 'second.txt'), 'more data\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'second commit');
        await git(a, 'push', remoteUrl(), 'main');

        // Append model: second push adds a new pack object, keeps the first.
        const packs = (await list(client, `${repoId}/packs/`)).sort();
        assert.equal(packs.length, 2, 'one pack per push');

        const c = join(work, 'repo-c');
        await git(work, 'clone', remoteUrl(), c);
        assert.equal(await readFile(join(c, 'second.txt'), 'utf8'), 'more data\n');
        const { stdout: log } = await git(c, 'log', '--format=%s', 'main');
        assert.deepEqual(log.trim().split('\n'), ['second commit', 'first commit']);
    });

    test('stale push is rejected (refs CAS / non-fast-forward), then succeeds after pull', { skip: !reachable }, async () => {
        // repo-b is now one commit behind repo-a's second push. Give it a
        // divergent commit and push — must be rejected, not clobber the manifest.
        const b = join(work, 'repo-b');
        await writeFile(join(b, 'divergent.txt'), 'divergent\n');
        await git(b, 'add', '.');
        await git(b, 'commit', '-m', 'divergent commit');
        await assert.rejects(
            () => git(b, 'push', remoteUrl(), 'main'),
            /non-fast-forward|fetch first|rejected/i,
            'stale push must be rejected'
        );

        // After rebasing onto the remote tip, the push goes through…
        await git(b, 'pull', '--rebase', remoteUrl(), 'main');
        await git(b, 'push', remoteUrl(), 'main');

        // …and a fresh clone sees all three commits.
        const d = join(work, 'repo-d');
        await git(work, 'clone', remoteUrl(), d);
        const { stdout: log } = await git(d, 'log', '--format=%s', 'main');
        assert.deepEqual(log.trim().split('\n'), ['divergent commit', 'second commit', 'first commit']);
    });

    test('clone with the wrong key fails, leaking nothing', { skip: !reachable }, async () => {
        const e = join(work, 'repo-e');
        await assert.rejects(
            () => execFileP('git', ['clone', remoteUrl(), e], {
                cwd: work, env: { ...env, EGIT_KEY: 'b'.repeat(64) },
            }),
            'clone with a wrong key must fail'
        );
    });

    test('credentials from git config (egit.key/egit.auth) when the env is unset', { skip: !reachable }, async () => {
        // No EGIT_KEY/EGIT_AUTH in the environment at all.
        const { EGIT_KEY, EGIT_AUTH, ...envNoCreds } = env;

        // Without a key anywhere the helper must refuse with a hint at both sources.
        const f0 = join(work, 'repo-f0');
        await assert.rejects(
            () => execFileP('git', ['clone', remoteUrl(), f0], { cwd: work, env: envNoCreds }),
            /EGIT_KEY|egit\.key/,
            'missing key must name both credential sources'
        );

        // Clone bootstraps via inline config: `git -c egit.key=…` reaches the
        // helper through GIT_CONFIG_PARAMETERS.
        const f = join(work, 'repo-f');
        await execFileP('git', ['-c', `egit.key=${KEY_HEX}`, 'clone', remoteUrl(), f], {
            cwd: work, env: envNoCreds,
        });
        assert.equal(await readFile(join(f, 'hello.txt'), 'utf8'), 'hello encrypted world\n');

        // Persist the credentials in the repo config — plain git pull/push work
        // from here on, no env exports.
        await execFileP('git', ['config', 'egit.key', KEY_HEX], { cwd: f, env: envNoCreds });
        await execFileP('git', ['config', 'egit.auth', 'Bearer test-config-token'], { cwd: f, env: envNoCreds });
        await execFileP('git', ['pull', remoteUrl(), 'main'], { cwd: f, env: envNoCreds });
        await writeFile(join(f, 'from-config.txt'), 'pushed with git-config credentials\n');
        await execFileP('git', ['add', '.'], { cwd: f, env: envNoCreds });
        await execFileP('git', ['commit', '-m', 'config-credential push'], { cwd: f, env: envNoCreds });
        await execFileP('git', ['push', remoteUrl(), 'main'], { cwd: f, env: envNoCreds });

        // The environment still wins over config: a wrong env key must fail even
        // though the repo config holds the right one.
        await assert.rejects(
            () => execFileP('git', ['pull', remoteUrl(), 'main'], {
                cwd: f, env: { ...envNoCreds, EGIT_KEY: 'b'.repeat(64) },
            }),
            'env EGIT_KEY must take precedence over git config'
        );

        // And the config-credential push is really in the store.
        const g = join(work, 'repo-g');
        await git(work, 'clone', remoteUrl(), g);
        assert.equal(await readFile(join(g, 'from-config.txt'), 'utf8'), 'pushed with git-config credentials\n');
    });
});

describe('remote-helper content variety and multi-ref sync', () => {
    const repo2 = `cli-test-content-${Date.now()}`;
    const remote2 = () => `egit::${proxyUrl}/${repo2}`;
    // Deterministic pseudo-random bytes: incompressible, so pack size ≈ content size.
    const noise = (len, seed = 1) => {
        const out = Buffer.alloc(len);
        let s = seed >>> 0 || 1; // xorshift32 — genuinely incompressible output
        for (let i = 0; i < len; i++) {
            s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
            out[i] = s & 0xff;
        }
        return out;
    };

    after(async () => {
        if (reachable) for (const k of await list(client, `${repo2}/`)) await del(client, k).catch(() => {});
    });

    test('clone of an empty remote, then first push from that clone', { skip: !reachable }, async () => {
        const a = join(work, 'content-a');
        await git(work, 'clone', remote2(), a); // no refs manifest yet — "empty repository" clone
        await git(a, 'checkout', '-b', 'main');
        await writeFile(join(a, 'seed.txt'), 'seed\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'seed');
        await git(a, 'push', 'origin', 'main');
    });

    test('binary + sizable + nested + unicode content round-trips', { skip: !reachable }, async () => {
        const a = join(work, 'content-a');
        await mkdir(join(a, 'nested/deep'), { recursive: true });
        const big = noise(2 * 1024 * 1024); // ~2MB incompressible binary
        await writeFile(join(a, 'blob.bin'), big);
        await writeFile(join(a, 'nested/deep/ünïcödé 文件.txt'), 'unicode filename + content: ✓ ✔ 中文\n');
        await writeFile(join(a, 'compressible.txt'), 'repeat me\n'.repeat(50_000));
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'binary and friends');
        await git(a, 'push', 'origin', 'main');

        const b = join(work, 'content-b');
        await git(work, 'clone', remote2(), b);
        assert.deepEqual(await readFile(join(b, 'blob.bin')), big, 'binary survives byte-exact');
        assert.equal(
            await readFile(join(b, 'nested/deep/ünïcödé 文件.txt'), 'utf8'),
            'unicode filename + content: ✓ ✔ 中文\n');
        // The sizable pack is really in the store, encrypted.
        const packs = await list(client, `${repo2}/packs/`);
        let stored = 0;
        for (const k of packs) stored += (await getBytes(client, k)).length;
        assert.ok(stored > 2 * 1024 * 1024, `store holds the ~2MB push (got ${stored} bytes)`);
    });

    test('branches and annotated tags sync; branch deletion propagates', { skip: !reachable }, async () => {
        const a = join(work, 'content-a');
        await git(a, 'checkout', '-b', 'feature');
        await writeFile(join(a, 'feature.txt'), 'feature work\n');
        await git(a, 'add', '.');
        await git(a, 'commit', '-m', 'feature commit');
        await git(a, 'tag', '-a', 'v1.0', '-m', 'release v1.0');
        await git(a, 'push', 'origin', 'main', 'feature', 'v1.0');

        const b = join(work, 'content-tags');
        await git(work, 'clone', remote2(), b);
        const { stdout: refs } = await git(b, 'ls-remote', 'origin');
        assert.match(refs, /refs\/heads\/main/);
        assert.match(refs, /refs\/heads\/feature/);
        assert.match(refs, /refs\/tags\/v1\.0/);
        const { stdout: tagMsg } = await git(b, 'tag', '-l', '-n1', 'v1.0');
        assert.match(tagMsg, /release v1\.0/, 'annotated tag object came through');
        assert.equal(await readFile(join(b, 'feature.txt'), 'utf8').catch(() => null), null,
            'clone checked out main (HEAD symref), not feature');

        // Delete the branch on the remote; a fresh ls-remote no longer shows it.
        await git(a, 'push', 'origin', ':feature');
        const { stdout: refsAfter } = await git(b, 'ls-remote', 'origin');
        assert.doesNotMatch(refsAfter, /refs\/heads\/feature/);
        assert.match(refsAfter, /refs\/tags\/v1\.0/, 'tag survives branch deletion');
    });

    test('ping-pong: two clones alternate pushes and converge (delta chains across packs)', { skip: !reachable }, async () => {
        const a = join(work, 'content-a');
        await git(a, 'checkout', 'main'); // the tags test left repo-a on `feature`
        const b = join(work, 'content-pp');
        await git(work, 'clone', remote2(), b);

        // Several rounds mutating the SAME large file → thin packs whose delta
        // bases live in earlier packs, exactly what fetch must replay in order.
        for (let round = 0; round < 3; round++) {
            const pusher = round % 2 === 0 ? a : b;
            await git(pusher, 'pull', '--rebase', 'origin', 'main'); // sync before mutating
            const grown = noise(512 * 1024, round + 10);
            await writeFile(join(pusher, 'blob.bin'), grown);
            await writeFile(join(pusher, `round-${round}.txt`), `round ${round}\n`);
            await git(pusher, 'add', '.');
            await git(pusher, 'commit', '-m', `round ${round}`);
            await git(pusher, 'push', 'origin', 'main');
        }

        await git(a, 'pull', '--rebase', 'origin', 'main');
        await git(b, 'pull', '--rebase', 'origin', 'main');
        const { stdout: shaA } = await git(a, 'rev-parse', 'main');
        const { stdout: shaB } = await git(b, 'rev-parse', 'main');
        assert.equal(shaA, shaB, 'both clones converge on the same tip');
        assert.deepEqual(await readFile(join(a, 'blob.bin')), await readFile(join(b, 'blob.bin')));

        // And a cold clone replays the whole growing history correctly.
        const c = join(work, 'content-cold');
        await git(work, 'clone', remote2(), c);
        const { stdout: shaC } = await git(c, 'rev-parse', 'main');
        assert.equal(shaC, shaA);
        await git(c, 'fsck', '--strict'); // full object-graph integrity after replaying all packs
    });
});
