// Service-worker scenario: wasm-git in a worker, all git traffic intercepted by
// src/service-worker/sw.js and served from the encrypted store (proxy → MinIO).
import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, getBytes, list } from '../helpers/minio.mjs';
import { isEncrypted } from '../../src/core/crypto.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const KEY_HEX = 'd'.repeat(64);
const repoId = `e2e-sw-${Date.now()}`;
const client = makeClient();

// CLI-side helpers (seed/verify against the same store from node, via the remote helper)
async function cliEnv() {
    const work = await mkdtemp(join(tmpdir(), 'egit-e2e-'));
    const bin = join(work, 'bin');
    await mkdir(bin);
    await chmod(HELPER, 0o755);
    await symlink(HELPER, join(bin, 'git-remote-egit'));
    return {
        work,
        env: {
            ...process.env,
            PATH: `${bin}:${process.env.PATH}`,
            EGIT_KEY: KEY_HEX,
            GIT_AUTHOR_NAME: 'CLI', GIT_AUTHOR_EMAIL: 'cli@example.com',
            GIT_COMMITTER_NAME: 'CLI', GIT_COMMITTER_EMAIL: 'cli@example.com',
        },
    };
}
const git = (env, cwd, ...args) => execFileP('git', args, { cwd, env });

async function bootPage(page) {
    await page.goto('/');
    await page.waitForFunction(() => window.egitReady === true);
    await page.evaluate(([id, key]) => window.egit.setKey(id, key), [repoId, KEY_HEX]);
}
const egit = (page, op, args) =>
    page.evaluate(([op, args]) => window.egit.call(op, args), [op, args]);

test.beforeAll(async () => { await ensureBucket(client); });

test('SW: clone → commit → push → fresh re-clone matches', async ({ page }) => {
    test.setTimeout(120_000);
    // Seed the repo from the CLI so the browser clones something real.
    const { work, env } = await cliEnv();
    const seed = join(work, 'seed');
    await mkdir(seed);
    await git(env, seed, 'init', '-b', 'main');
    await writeFile(join(seed, 'hello.txt'), 'hello from the CLI\n');
    await git(env, seed, 'add', '.');
    await git(env, seed, 'commit', '-m', 'seed');
    await git(env, seed, 'push', `egit::http://127.0.0.1:8787/store/${repoId}`, 'main');

    await bootPage(page);
    const variant = await egit(page, 'variant');
    console.log(`wasm-git OPFS variant: ${variant}`);

    // Clone through the service worker.
    const files = await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'repo' });
    expect(files).toContain('hello.txt');
    expect(await egit(page, 'readFile', { repoName: 'repo', filename: 'hello.txt' }))
        .toBe('hello from the CLI\n');

    // Commit + push from the browser.
    await egit(page, 'writeFile', { repoName: 'repo', filename: 'from-browser.txt', contents: 'written in the browser\n' });
    await egit(page, 'addCommitPush', { repoName: 'repo', filename: 'from-browser.txt', message: 'browser commit' });

    // Fresh re-clone (separate repo dir) sees the browser's push.
    await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'repo2' });
    expect(await egit(page, 'readFile', { repoName: 'repo2', filename: 'from-browser.txt' }))
        .toBe('written in the browser\n');
    expect(await egit(page, 'readFile', { repoName: 'repo2', filename: 'hello.txt' }))
        .toBe('hello from the CLI\n');
});

test('SW: the object store holds only ciphertext (zero-knowledge)', async () => {
    const keys = await list(client, `${repoId}/`);
    expect(keys.length).toBeGreaterThanOrEqual(3); // refs + seed pack + browser pack
    for (const key of keys) {
        const bytes = await getBytes(client, key);
        expect(isEncrypted(bytes)).toBe(true);
        expect(bytes.includes(Buffer.from('PACK'))).toBe(false);
        expect(bytes.includes(Buffer.from('refs/heads'))).toBe(false);
    }
});
