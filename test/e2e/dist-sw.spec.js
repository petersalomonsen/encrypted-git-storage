// Consumability, browser side: register the BUNDLED dist/sw.js (what a consumer
// app serves at its own scope — built by `npm run build` / the package's
// `prepare`) instead of the source module, and run a real wasm-git clone +
// push through it.
import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket } from '../helpers/minio.mjs';

const execFileP = promisify(execFile);
const ROOT = resolve(fileURLToPath(import.meta.url), '../../..');
const HELPER = join(ROOT, 'src/remote-helper/git-remote-egit.js');

const KEY_HEX = '9'.repeat(64);
const repoId = `dist-sw-${Date.now()}`;

const egit = (page, op, args) =>
    page.evaluate(([op, args]) => window.egit.call(op, args), [op, args]);

test.beforeAll(async () => {
    await ensureBucket(makeClient());
    await execFileP('npm', ['run', 'build'], { cwd: ROOT }); // ensure dist/sw.js is current
});

test('bundled dist/sw.js serves a full clone → push → re-clone round-trip', async ({ page }) => {
    test.setTimeout(120_000);
    // Seed via the CLI remote helper.
    const work = await mkdtemp(join(tmpdir(), 'egit-dist-'));
    const bin = join(work, 'bin');
    await mkdir(bin);
    await chmod(HELPER, 0o755);
    await symlink(HELPER, join(bin, 'git-remote-egit'));
    const env = {
        ...process.env, PATH: `${bin}:${process.env.PATH}`, EGIT_KEY: KEY_HEX,
        GIT_AUTHOR_NAME: 'CLI', GIT_AUTHOR_EMAIL: 'cli@example.com',
        GIT_COMMITTER_NAME: 'CLI', GIT_COMMITTER_EMAIL: 'cli@example.com',
    };
    const seed = join(work, 'seed');
    await mkdir(seed);
    const git = (cwd, ...args) => execFileP('git', args, { cwd, env });
    await git(seed, 'init', '-b', 'main');
    await writeFile(join(seed, 'hello.txt'), 'served by the bundle\n');
    await git(seed, 'add', '.');
    await git(seed, 'commit', '-m', 'seed');
    await git(seed, 'push', `egit::http://127.0.0.1:8787/store/${repoId}`, 'main');

    // Register the BUNDLE, not the source module.
    await page.goto('/?sw=%2Fdist%2Fsw.js');
    await page.waitForFunction(() => window.egitReady === true);
    expect(await page.evaluate(() => navigator.serviceWorker.controller.scriptURL))
        .toContain('/dist/sw.js');
    await page.evaluate(([id, key]) => window.egit.setKey(id, key), [repoId, KEY_HEX]);

    await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'r' });
    expect(await egit(page, 'readFile', { repoName: 'r', filename: 'hello.txt' }))
        .toBe('served by the bundle\n');

    await egit(page, 'writeFile', { repoName: 'r', filename: 'bundle.txt', contents: 'pushed via dist bundle\n' });
    await egit(page, 'addCommitPush', { repoName: 'r', filename: 'bundle.txt', message: 'via bundle' });

    await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'r2' });
    expect(await egit(page, 'readFile', { repoName: 'r2', filename: 'bundle.txt' }))
        .toBe('pushed via dist bundle\n');
});
