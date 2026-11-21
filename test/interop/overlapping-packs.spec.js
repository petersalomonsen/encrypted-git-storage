// A store whose packs overlap must still be readable by the browser.
//
// Every push is built against the remote TIP only, so a push that brings a
// file back to content an OLDER commit had re-sends objects the store already
// holds — from the CLI and from the browser alike, no merge involved. The
// store keeps one pack per push and serves them merged into one; libgit2
// (wasm-git) refuses a pack with an object in it twice, and a failed clone
// leaves an EMPTY repository behind. This is what happened to a real store:
// new devices "synced" and got nothing.
//
// Each test here first proves the store really holds a duplicate (decrypting
// and indexing its packs), then that the browser reads it anyway.
import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, readFile, symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, getBytes } from '../helpers/minio.mjs';
import { decrypt } from '../../src/core/crypto.js';
import { makeStoreClient } from '../../src/core/store-client.js';
import { loadManifest } from '../../src/core/manifest-io.js';
import { packsInOrder } from '../../src/core/format.js';
import { indexPacks } from '../../src/core/packindex.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');
const KEY_HEX = 'f'.repeat(64);
const KEY = Uint8Array.from(KEY_HEX.match(/../g), (h) => parseInt(h, 16));
const repoId = `overlap-${Date.now()}`;
const REMOTE_CLI = `egit::http://127.0.0.1:8787/store/${repoId}`;
const REMOTE_SW = `http://127.0.0.1:8787/egit/${repoId}`;
const client = makeClient();

let work, env, cli;
const git = (cwd, ...args) => execFileP('git', args, { cwd, env, maxBuffer: 1 << 26 });

// JSON-ish price history, big enough to be stored as deltas.
const prices = (days, extra = '') => {
    const lines = [];
    for (let d = 0; d < days; d++) lines.push(`  "2026-${String(1 + (d % 12)).padStart(2, '0')}-${String(1 + (d % 28)).padStart(2, '0')}#${d}": ${(d * 7919) % 1000 / 100},`);
    return `{\n${lines.join('\n')}\n  "x": 0${extra}\n}\n`;
};
const V1 = prices(4000);
const V2 = prices(4000, ',\n  "merged-in": 1');

/** Total and distinct object counts across the packs the store holds. */
async function storeObjects() {
    const store = makeStoreClient(`http://127.0.0.1:8787/store/${repoId}`, repoId);
    const { manifest } = await loadManifest(store, KEY);
    const packs = [];
    for (const p of packsInOrder(manifest)) packs.push(await decrypt(KEY, await store.getPack(p.n)));
    const oids = (await indexPacks(packs)).flat().map((e) => e.oid);
    return { packs: packs.length, total: oids.length, distinct: new Set(oids).size };
}

async function bootPage(page) {
    await page.goto('/');
    await page.waitForFunction(() => window.egitReady === true);
    await page.evaluate(([id, key]) => window.egit.setKey(id, key), [repoId, KEY_HEX]);
}
const egit = (page, op, args) => page.evaluate(([op, args]) => window.egit.call(op, args), [op, args]);

test.beforeAll(async () => {
    await ensureBucket(client);
    work = await mkdtemp(join(tmpdir(), 'egit-overlap-'));
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
    cli = join(work, 'cli');
    await mkdir(join(cli, 'pricehistory', 'NEAR'), { recursive: true });
    await git(cli, 'init', '-b', 'master');
});

test('CLI: a plain commit restoring older content leaves duplicates; a fresh browser still clones', async ({ page }) => {
    test.setTimeout(180_000);
    const usd = join(cli, 'pricehistory', 'NEAR', 'usd.json');
    await writeFile(usd, V1);
    await writeFile(join(cli, 'accounts.json'), '["a.near"]\n');
    await git(cli, 'add', '.');
    await git(cli, 'commit', '-m', 'A');
    await git(cli, 'push', REMOTE_CLI, 'master');

    await writeFile(usd, V2); // another device's merge changed it
    await git(cli, 'commit', '-am', 'B');
    await git(cli, 'push', REMOTE_CLI, 'master');

    await writeFile(usd, V1); // and this one puts it back
    await writeFile(join(cli, 'accounts.json'), '["a.near","b.near"]\n');
    await git(cli, 'commit', '-am', 'C restores usd.json');
    await git(cli, 'push', REMOTE_CLI, 'master');

    const held = await storeObjects();
    expect(held.packs).toBe(3);
    expect(held.total, 'the store really holds an object twice').toBeGreaterThan(held.distinct);

    await bootPage(page);
    const files = await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });
    expect(files).toEqual(expect.arrayContaining(['accounts.json', 'pricehistory']));
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'pricehistory/NEAR/usd.json' })).toBe(V1);
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'accounts.json' })).toBe('["a.near","b.near"]\n');
});

test('browser (libgit2): its own restoring push adds duplicates; another fresh browser and the CLI still read it', async ({ page, browser }) => {
    test.setTimeout(180_000);
    await bootPage(page);
    await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });
    const before = await storeObjects();

    // Back to B's content: libgit2 hides only the tip (C), so it re-sends V2.
    await egit(page, 'writeFile', { repoName: 'w', filename: 'pricehistory/NEAR/usd.json', contents: V2 });
    await egit(page, 'addCommitPush', { repoName: 'w', filename: 'pricehistory/NEAR/usd.json', message: 'browser restores V2' });
    const after = await storeObjects();
    expect(after.packs).toBe(before.packs + 1);
    expect(after.total - after.distinct, 'the browser push re-sent a stored object')
        .toBeGreaterThan(before.total - before.distinct);

    // A brand-new device: fresh context, empty OPFS.
    const ctx = await browser.newContext();
    const fresh = await ctx.newPage();
    await bootPage(fresh);
    const files = await egit(fresh, 'clone', { url: REMOTE_SW, repoName: 'w' });
    expect(files).toEqual(expect.arrayContaining(['accounts.json', 'pricehistory']));
    expect(await egit(fresh, 'readFile', { repoName: 'w', filename: 'pricehistory/NEAR/usd.json' })).toBe(V2);
    await ctx.close();

    const c = join(work, 'cli-clone');
    await git(work, 'clone', REMOTE_CLI, c);
    await git(c, 'fsck', '--strict');
    expect(await readFile(join(c, 'pricehistory', 'NEAR', 'usd.json'), 'utf8')).toBe(V2);
});

test('an existing browser clone FETCHES a push that duplicated objects', async ({ page }) => {
    test.setTimeout(180_000);
    await bootPage(page);
    await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w' });

    // The CLI (behind: still at C) pulls, then restores V1 once more.
    await git(cli, 'pull', '--rebase', REMOTE_CLI, 'master');
    await writeFile(join(cli, 'pricehistory', 'NEAR', 'usd.json'), V1);
    await git(cli, 'commit', '-am', 'D restores V1 again');
    await git(cli, 'push', REMOTE_CLI, 'master');
    const held = await storeObjects();
    expect(held.total).toBeGreaterThan(held.distinct);

    await egit(page, 'run', { repoName: 'w', args: ['fetch', 'origin'] });
    await egit(page, 'run', { repoName: 'w', args: ['checkout', 'origin/master'] });
    expect(await egit(page, 'readFile', { repoName: 'w', filename: 'pricehistory/NEAR/usd.json' })).toBe(V1);
});

test('compacting a store with duplicates keeps one copy of each object', async ({ page }) => {
    test.setTimeout(180_000);
    const before = await storeObjects();
    await bootPage(page);
    const result = await egit(page, 'compact', { repoId, keyHex: KEY_HEX });
    expect(result.packsAfter).toBe(1);
    const after = await storeObjects();
    expect(after).toEqual({ packs: 1, total: before.distinct, distinct: before.distinct });

    const files = await egit(page, 'clone', { url: REMOTE_SW, repoName: 'w2' });
    expect(files).toEqual(expect.arrayContaining(['accounts.json', 'pricehistory']));
    expect(await egit(page, 'readFile', { repoName: 'w2', filename: 'pricehistory/NEAR/usd.json' })).toBe(V1);
});
