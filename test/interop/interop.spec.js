// The acceptance test: the browser (wasm-git behind the service worker) and the
// CLI (git + git-remote-egit) share one encrypted store with the same key and
// must read each other's writes — including as the repo grows over multiple
// commits from both sides and carries sizable binary content.
//
//   browser: wasm-git ──smart HTTP──> SW ─────┐
//   CLI:     git ──remote-helper──> egit ─────┴─> gateway /store ──> MinIO (ciphertext)
import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile } from 'node:fs/promises';
import { symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, getBytes, list } from '../helpers/minio.mjs';
import { isEncrypted } from '../../src/core/crypto.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const KEY_HEX = 'e'.repeat(64);
const repoId = `interop-${Date.now()}`;
const REMOTE_CLI = `egit::http://127.0.0.1:8787/store/${repoId}`;
const REMOTE_SW = `http://127.0.0.1:8787/egit/${repoId}`;
const client = makeClient();

// Same xorshift32 as test/e2e/page/worker.js — both sides generate identical
// bytes from a seed, so binary integrity is checked by hash, not by transfer.
function noise(len, seed) {
    const out = Buffer.alloc(len);
    let s = seed >>> 0 || 1;
    for (let i = 0; i < len; i++) {
        s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
        out[i] = s & 0xff;
    }
    return out;
}
const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

let work, env;
const git = (cwd, ...args) => execFileP('git', args, { cwd, env });

async function bootPage(page) {
    await page.goto('/');
    await page.waitForFunction(() => window.egitReady === true);
    await page.evaluate(([id, key]) => window.egit.setKey(id, key), [repoId, KEY_HEX]);
}
const egit = (page, op, args) =>
    page.evaluate(([op, args]) => window.egit.call(op, args), [op, args]);

test.beforeAll(async () => {
    await ensureBucket(client);
    work = await mkdtemp(join(tmpdir(), 'egit-interop-'));
    const bin = join(work, 'bin');
    await mkdir(bin);
    await chmod(HELPER, 0o755);
    await symlink(HELPER, join(bin, 'git-remote-egit'));
    env = {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        EGIT_KEY: KEY_HEX,
        GIT_AUTHOR_NAME: 'CLI', GIT_AUTHOR_EMAIL: 'cli@example.com',
        GIT_COMMITTER_NAME: 'CLI', GIT_COMMITTER_EMAIL: 'cli@example.com',
    };
});

test('CLI builds a growing repo (multiple commits, ~3MB binary) → browser clone matches', async ({ page }) => {
    test.setTimeout(180_000);
    const a = join(work, 'cli-a');
    await mkdir(a);
    await git(a, 'init', '-b', 'main');

    // Growth: several pushes, including sizable binary content and a rewrite.
    await writeFile(join(a, 'readme.md'), '# interop\n');
    await git(a, 'add', '.');
    await git(a, 'commit', '-m', 'init');
    await git(a, 'push', REMOTE_CLI, 'main');

    await writeFile(join(a, 'big.bin'), noise(3 * 1024 * 1024, 7));
    await git(a, 'add', '.');
    await git(a, 'commit', '-m', 'add 3MB binary');
    await git(a, 'push', REMOTE_CLI, 'main');

    await writeFile(join(a, 'big.bin'), noise(3 * 1024 * 1024, 8)); // full rewrite
    await writeFile(join(a, 'notes.txt'), 'plain text\n'.repeat(10_000));
    await git(a, 'add', '.');
    await git(a, 'commit', '-m', 'rewrite binary + text');
    await git(a, 'push', REMOTE_CLI, 'main');

    // Browser clones the whole thing through the SW (3 packs merged on the fly).
    await bootPage(page);
    const files = await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });
    expect(files).toEqual(expect.arrayContaining(['readme.md', 'big.bin', 'notes.txt']));
    expect(await egit(page, 'hashFile', { repoName: 'w', filename: 'big.bin' }))
        .toBe(sha256(noise(3 * 1024 * 1024, 8)));
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'readme.md' })).toBe('# interop\n');
});

test('browser pushes growth (multiple commits incl. 1MB binary) → CLI clone matches', async ({ page }) => {
    test.setTimeout(180_000);
    await bootPage(page);
    await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });

    // Multiple browser-side commits, each pushed (a pack per push).
    await egit(page, 'writeNoise', { repoName: 'w', filename: 'browser.bin', size: 1024 * 1024, seed: 42 });
    await egit(page, 'addCommitPush', { repoName: 'w', filename: 'browser.bin', message: 'browser adds 1MB binary' });

    await egit(page, 'writeFile', { repoName: 'w', filename: 'browser.txt', contents: 'browser text\n' });
    await egit(page, 'addCommitPush', { repoName: 'w', filename: 'browser.txt', message: 'browser adds text' });

    await egit(page, 'writeNoise', { repoName: 'w', filename: 'browser.bin', size: 1024 * 1024 + 512, seed: 43 });
    await egit(page, 'addCommitPush', { repoName: 'w', filename: 'browser.bin', message: 'browser rewrites binary' });

    // CLI clones via the remote helper and verifies bytes + full object graph.
    const b = join(work, 'cli-b');
    await git(work, 'clone', REMOTE_CLI, b);
    expect(sha256(await readFile(join(b, 'browser.bin')))).toBe(sha256(noise(1024 * 1024 + 512, 43)));
    expect(await readFile(join(b, 'browser.txt'), 'utf8')).toBe('browser text\n');
    expect(sha256(await readFile(join(b, 'big.bin')))).toBe(sha256(noise(3 * 1024 * 1024, 8)));
    await git(b, 'fsck', '--strict');

    const { stdout: log } = await git(b, 'log', '--format=%s', 'main');
    expect(log.trim().split('\n')).toEqual([
        'browser rewrites binary',
        'browser adds text',
        'browser adds 1MB binary',
        'rewrite binary + text',
        'add 3MB binary',
        'init',
    ]);
});

test('ping-pong continues: CLI push → browser fetch sees it; browser push → CLI pull', async ({ page }) => {
    test.setTimeout(180_000);
    // CLI adds one more commit on top of the browser's work.
    const b = join(work, 'cli-b');
    await writeFile(join(b, 'round2-cli.txt'), 'cli again\n');
    await git(b, 'add', '.');
    await git(b, 'commit', '-m', 'cli round 2');
    await git(b, 'push', 'origin', 'main');

    // Browser: fresh context → clone (includes CLI's new commit), then reply.
    await bootPage(page);
    await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'round2-cli.txt' })).toBe('cli again\n');
    await egit(page, 'writeFile', { repoName: 'w', filename: 'round2-browser.txt', contents: 'browser again\n' });
    await egit(page, 'addCommitPush', { repoName: 'w', filename: 'round2-browser.txt', message: 'browser round 2' });

    // Browser-side incremental fetch must also work through the SW (upload-pack
    // negotiation with haves): CLI pushes once more, browser fetches into the
    // SAME clone rather than re-cloning.
    await git(b, 'pull', '--rebase', 'origin', 'main');
    expect(await readFile(join(b, 'round2-browser.txt'), 'utf8')).toBe('browser again\n');
    await writeFile(join(b, 'round3-cli.txt'), 'cli round 3\n');
    await git(b, 'add', '.');
    await git(b, 'commit', '-m', 'cli round 3');
    await git(b, 'push', 'origin', 'main');

    await egit(page, 'run', { repoName: 'w', args: ['fetch', 'origin'] });
    await egit(page, 'run', { repoName: 'w', args: ['checkout', 'origin/main'] });
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'round3-cli.txt' })).toBe('cli round 3\n');

    // CLI's final view converges with everything.
    await git(b, 'pull', '--rebase', 'origin', 'main');
    await git(b, 'fsck', '--strict');
});

test('after all of that: the store still holds only ciphertext, one pack per push', async () => {
    const keys = await list(client, `${repoId}/`);
    const packs = keys.filter(k => k.includes('/packs/'));
    // 3 CLI + 3 browser + 1 CLI + 1 browser + 1 CLI pushes = 9 packs
    expect(packs.length).toBe(9);
    for (const key of keys) {
        const bytes = await getBytes(client, key);
        expect(isEncrypted(bytes)).toBe(true);
        expect(bytes.includes(Buffer.from('PACK'))).toBe(false);
        expect(bytes.includes(Buffer.from('refs/heads'))).toBe(false);
        expect(bytes.includes(Buffer.from('browser'))).toBe(false); // no filename/content leakage
    }
});

test('the BROWSER compacts the store (9 packs → 1); both sides still read everything', async ({ page }) => {
    test.setTimeout(180_000);
    await bootPage(page);
    const result = await egit(page, 'compact', { repoId, keyHex: KEY_HEX });
    expect(result.packsBefore).toBe(9);
    expect(result.packsAfter).toBe(1);

    const packs = (await list(client, `${repoId}/`)).filter(k => k.includes('/packs/'));
    expect(packs.length).toBe(1);
    expect(isEncrypted(await getBytes(client, packs[0]))).toBe(true);

    // CLI still clones the full history from the single compacted pack…
    const c = join(work, 'cli-compacted');
    await git(work, 'clone', REMOTE_CLI, c);
    await git(c, 'fsck', '--strict');
    expect(sha256(await readFile(join(c, 'big.bin')))).toBe(sha256(noise(3 * 1024 * 1024, 8)));
    expect(await readFile(join(c, 'round3-cli.txt'), 'utf8')).toBe('cli round 3\n');

    // …and so does the browser, through the SW.
    await egit(page, 'clone', { url: REMOTE_SW, repoName: 'wc' });
    expect(await egit(page, 'hashFile', { repoName: 'wc', filename: 'big.bin' }))
        .toBe(sha256(noise(3 * 1024 * 1024, 8)));
    expect(await egit(page, 'readFile', { repoName: 'wc', filename: 'round2-browser.txt' }))
        .toBe('browser again\n');
});
