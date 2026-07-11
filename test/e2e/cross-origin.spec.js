// Production topology test: the page (127.0.0.1:8787 — stands in for
// arizportfolio.near.page) talks to a gateway on a DIFFERENT origin
// (127.0.0.1:<ephemeral> — stands in for arizgateway.fly.dev) that requires the
// consumer's own auth header. Store traffic from the service worker goes
// cross-origin: preflighted PUTs (Authorization + content-type + If-Match),
// exposed ETag for the refs CAS, and per-repo config via egit-set-key.
import { test, expect } from '@playwright/test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { symlink, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeClient, ensureBucket, list, del } from '../helpers/minio.mjs';
import { createProxy } from '../../src/gateway/proxy.js';

const execFileP = promisify(execFile);
const HELPER = resolve(fileURLToPath(import.meta.url), '../../../src/remote-helper/git-remote-egit.js');

const PAGE_ORIGIN = 'http://127.0.0.1:8787';
const KEY_HEX = '7'.repeat(64);
const TOKEN = 'Bearer cross-origin-test-token';
const repoId = `xorigin-${Date.now()}`;
const client = makeClient();

let gateway, gatewayOrigin, work, env;
const storeBase = () => `${gatewayOrigin}/${repoId}`;

const egit = (page, op, args) =>
    page.evaluate(([op, args]) => window.egit.call(op, args), [op, args]);

test.beforeAll(async () => {
    await ensureBucket(client);

    // Foreign-origin gateway: bearer-token auth (stand-in for Ariz's NEP-413),
    // CORS restricted to the page's origin.
    const app = createProxy({
        allowedOrigins: [PAGE_ORIGIN],
        auth: (req) => (req.header('authorization') === TOKEN ? req.params.repoId : null),
    });
    gateway = await new Promise((res) => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
    gatewayOrigin = `http://127.0.0.1:${gateway.address().port}`;

    work = await mkdtemp(join(tmpdir(), 'egit-xorigin-'));
    const bin = join(work, 'bin');
    await mkdir(bin);
    await chmod(HELPER, 0o755);
    await symlink(HELPER, join(bin, 'git-remote-egit'));
    env = {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        EGIT_KEY: KEY_HEX,
        EGIT_AUTH: TOKEN,
        GIT_AUTHOR_NAME: 'CLI', GIT_AUTHOR_EMAIL: 'cli@example.com',
        GIT_COMMITTER_NAME: 'CLI', GIT_COMMITTER_EMAIL: 'cli@example.com',
    };
});

test.afterAll(async () => {
    gateway?.close();
    for (const k of await list(client, `${repoId}/`)) await del(client, k).catch(() => {});
});

test('gateway enforces the auth header and answers CORS preflight correctly', async () => {
    // No auth → 401.
    expect((await fetch(`${storeBase()}/refs`)).status).toBe(401);
    // Wrong token → 401.
    expect((await fetch(`${storeBase()}/refs`, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);

    // Preflight from the allowed origin: 204 + the CORS grants a PUT needs.
    const pre = await fetch(`${storeBase()}/refs`, {
        method: 'OPTIONS',
        headers: {
            origin: PAGE_ORIGIN,
            'access-control-request-method': 'PUT',
            'access-control-request-headers': 'authorization,content-type,if-match',
        },
    });
    expect(pre.status).toBe(204);
    expect(pre.headers.get('access-control-allow-origin')).toBe(PAGE_ORIGIN);
    expect(pre.headers.get('access-control-allow-methods')).toContain('PUT');
    expect(pre.headers.get('access-control-allow-headers')).toContain('authorization');

    // Preflight from a foreign origin gets no CORS grant (and no auth pass).
    const evil = await fetch(`${storeBase()}/refs`, {
        method: 'OPTIONS',
        headers: { origin: 'http://evil.example', 'access-control-request-method': 'PUT' },
    });
    expect(evil.headers.get('access-control-allow-origin')).toBeNull();
    expect(evil.status).toBe(401);
});

test('CLI: EGIT_AUTH rides on every store request; without it the push is rejected', async () => {
    const seed = join(work, 'seed');
    await mkdir(seed);
    const git = (cwd, ...args) => execFileP('git', args, { cwd, env });
    await git(seed, 'init', '-b', 'main');
    await writeFile(join(seed, 'hello.txt'), 'seeded cross-origin\n');
    await git(seed, 'add', '.');
    await git(seed, 'commit', '-m', 'seed');

    // Without EGIT_AUTH → gateway 401 → push fails.
    const noAuth = { ...env };
    delete noAuth.EGIT_AUTH;
    await expect(execFileP('git', ['push', `egit::${storeBase()}`, 'main'], { cwd: seed, env: noAuth }))
        .rejects.toThrow();

    // With it, the seed lands.
    await git(seed, 'push', `egit::${storeBase()}`, 'main');
});

test('SW round-trip against the foreign-origin store: clone → push → re-clone', async ({ page }) => {
    test.setTimeout(120_000);
    await page.goto('/');
    await page.waitForFunction(() => window.egitReady === true);

    // Misconfigured token first: store traffic must fail, not fall back.
    await page.evaluate(([id, key, store]) => window.egit.setKey(id, key, {
        storeBaseUrl: store, headers: { Authorization: 'Bearer wrong' },
    }), [repoId, KEY_HEX, storeBase()]);
    await expect(egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'x' }))
        .rejects.toThrow();

    // Re-send with the right token — config updates in place (token refresh path).
    await page.evaluate(([id, key, store, token]) => window.egit.setKey(id, key, {
        storeBaseUrl: store, headers: { Authorization: token },
    }), [repoId, KEY_HEX, storeBase(), TOKEN]);

    await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'x' });
    expect(await egit(page, 'readFile', { repoName: 'x', filename: 'hello.txt' }))
        .toBe('seeded cross-origin\n');

    // Push = preflighted cross-origin PUTs + If-Match CAS on the exposed ETag.
    await egit(page, 'writeFile', { repoName: 'x', filename: 'from-browser.txt', contents: 'cross-origin push\n' });
    await egit(page, 'addCommitPush', { repoName: 'x', filename: 'from-browser.txt', message: 'browser xorigin' });

    await egit(page, 'clone', { url: `http://127.0.0.1:8787/egit/${repoId}`, repoName: 'x2' });
    expect(await egit(page, 'readFile', { repoName: 'x2', filename: 'from-browser.txt' }))
        .toBe('cross-origin push\n');
});

test('CLI reads the browser push back through the foreign-origin gateway', async () => {
    const out = join(work, 'verify');
    await execFileP('git', ['clone', `egit::${storeBase()}`, out], { cwd: work, env });
    const { stdout } = await execFileP('git', ['log', '--format=%s', '-1'], { cwd: out, env });
    expect(stdout.trim()).toBe('browser xorigin');
});
