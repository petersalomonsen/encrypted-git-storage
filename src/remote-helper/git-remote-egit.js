#!/usr/bin/env node
// git remote helper for the `egit::` transport.
//
//   git clone egit::<proxy-url>/<repoId>
//   git push  egit::<proxy-url>/<repoId> main
//
// git invokes this with argv = [remoteName, url] and speaks the remote-helper
// protocol on stdin/stdout (`git help remote-helpers`). We implement the `fetch`
// and `push` capabilities by building/parsing packfiles with git's own plumbing
// (pack-objects / index-pack), encrypting them with ../core/crypto.js, and
// PUT/GET-ing them via the gateway proxy. The store never sees plaintext.
//
// Maintenance modes (invoked directly, not through git):
//   git-remote-egit --compact <url>       merge all packs into one (keeps all objects)
//   git-remote-egit --gc <url>            reachability repack: drops objects orphaned
//                                         by force-pushes/deleted branches, redeltifies
//   git-remote-egit --prune[=mins] <url>  delete unreferenced packs older than mins (60)
//
// The AES key comes from EGIT_KEY (64 hex chars or base64 for 32 bytes) in the
// environment (Ariz exports the wallet-derived key). ../core is shared verbatim
// with the service worker so both sides interoperate on the same store.

import process from 'node:process';
import { createInterface } from 'node:readline';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { encrypt, decrypt, sha256hex } from '../core/crypto.js';
import { nextPackIndex, advanceManifest, packsInOrder } from '../core/format.js';
import { loadManifest, encryptManifest } from '../core/manifest-io.js';
import { makeStoreClient } from '../core/store-client.js';
import { packObjectCount } from '../core/packcat.js';
import { compact, replacePacks, pruneOrphans } from '../core/maintenance.js';

// ---------------------------------------------------------------------------
// config from argv/env

function parseKey(raw) {
    if (!raw) throw new Error('EGIT_KEY not set — export the 32-byte repo key (hex or base64)');
    const bytes = /^[0-9a-fA-F]{64}$/.test(raw)
        ? Uint8Array.from(raw.match(/../g), h => parseInt(h, 16))
        : Uint8Array.from(Buffer.from(raw, 'base64'));
    if (bytes.length !== 32) throw new Error(`EGIT_KEY must decode to 32 bytes, got ${bytes.length}`);
    return bytes;
}

function parseRemoteUrl(url) {
    const stripped = url.replace(/^egit::/, '').replace(/\/+$/, '');
    const repoId = stripped.slice(stripped.lastIndexOf('/') + 1);
    if (!repoId) throw new Error(`cannot extract repoId from remote url: ${url}`);
    return { base: stripped, repoId };
}

// ---------------------------------------------------------------------------
// git plumbing (env is inherited, so GIT_DIR set by the parent git applies;
// stdout is always piped — the helper's own stdout is protocol-only)

function runGit(args, { stdin = null, cwd, env } = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn('git', args, { stdio: ['pipe', 'pipe', 'pipe'], cwd, env });
        const out = [], err = [];
        child.stdout.on('data', c => out.push(c));
        child.stderr.on('data', c => err.push(c));
        child.on('error', reject);
        child.on('close', code => resolve({
            code, stdout: Buffer.concat(out), stderr: Buffer.concat(err).toString(),
        }));
        if (stdin) child.stdin.write(stdin);
        child.stdin.end();
    });
}

async function gitOut(...args) {
    const r = await runGit(args);
    if (r.code !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr.trim()}`);
    return r.stdout.toString().trim();
}

const hasObject = async (sha) => (await runGit(['cat-file', '-e', sha])).code === 0;
const isAncestor = async (a, b) => (await runGit(['merge-base', '--is-ancestor', a, b])).code === 0;

/** Build a thin pack of `wantSha` minus objects reachable from `haves`. */
async function buildPack(wantSha, haves) {
    const revs = [wantSha, ...haves.map(h => `^${h}`), ''].join('\n');
    const r = await runGit(
        ['pack-objects', '--revs', '--thin', '--stdout', '--delta-base-offset', '-q'],
        { stdin: revs },
    );
    if (r.code !== 0) throw new Error(`git pack-objects failed: ${r.stderr.trim()}`);
    return new Uint8Array(r.stdout);
}

/** Store a pack's objects into the local repo (bases from earlier packs must already be present). */
async function indexPack(packBytes) {
    const r = await runGit(['index-pack', '--stdin', '--fix-thin'], { stdin: packBytes });
    if (r.code !== 0) throw new Error(`git index-pack failed: ${r.stderr.trim()}`);
}

// ---------------------------------------------------------------------------
// helper commands

function listRefs(manifest) {
    const lines = Object.entries(manifest.refs).map(([name, sha]) => `${sha} ${name}`);
    // Advertise a HEAD symref so clone checks out a sensible default branch.
    const head = manifest.refs['refs/heads/main'] ? 'refs/heads/main'
        : Object.keys(manifest.refs).find(r => r.startsWith('refs/heads/'));
    if (head) lines.push(`@${head} HEAD`);
    return lines;
}

async function doFetch(store, key) {
    // Download and replay every pack in order; earlier packs provide the thin-pack
    // bases for later ones. index-pack is idempotent for objects we already have.
    const { manifest } = await loadManifest(store, key);
    for (const p of packsInOrder(manifest)) {
        const pack = await decrypt(key, await store.getPack(p.n));
        if (packObjectCount(pack) === 0) continue;
        await indexPack(pack);
    }
}

/** One refspec push. Returns 'ok <dst>' / 'error <dst> <why>' protocol lines. */
async function doPush(store, key, spec) {
    const force = spec.startsWith('+');
    const [src, dst] = (force ? spec.slice(1) : spec).split(':');

    for (let attempt = 0; attempt < 5; attempt++) {
        const { manifest, etag } = await loadManifest(store, key);

        let refUpdates, pack = null, packBytes = null;
        if (!src) {
            if (!(dst in manifest.refs)) return `error ${dst} no such ref`;
            refUpdates = { [dst]: null }; // deletion
        } else {
            const srcSha = await gitOut('rev-parse', src);
            const old = manifest.refs[dst];
            if (old && !force) {
                if (!(await hasObject(old))) return `error ${dst} fetch first`;
                if (!(await isAncestor(old, srcSha))) return `error ${dst} non-fast-forward`;
            }
            // Exclude objects the remote already has (refs whose tips we hold locally).
            const haves = [];
            for (const sha of Object.values(manifest.refs)) {
                if (await hasObject(sha)) haves.push(sha);
            }
            packBytes = await buildPack(srcSha, haves);
            refUpdates = { [dst]: srcSha };
            if (packObjectCount(packBytes) > 0) {
                pack = { n: nextPackIndex(manifest), sha: await sha256hex(packBytes), size: packBytes.length };
                const encrypted = await encrypt(key, packBytes);
                while (!(await store.putPack(pack.n, encrypted))) pack.n++; // index taken by a racer
            }
        }

        const next = advanceManifest(manifest, { refUpdates, pack });
        if (await store.putRefs(await encryptManifest(key, next), etag)) {
            return `ok ${dst}`;
        }
        // CAS lost: someone else pushed. Reload and re-validate (fast-forward may
        // now fail). An already-stored pack stays — it only becomes referenced if
        // a later attempt succeeds; orphans are a compaction concern (see docs).
    }
    return `error ${dst} refs CAS kept failing — try again`;
}

// ---------------------------------------------------------------------------
// maintenance modes (run directly, not via git)

/**
 * Reachability-aware pack builder for --gc: replay every pack into a scratch
 * bare repo, then let git pack a single minimal pack of exactly the objects
 * reachable from the manifest's refs. Objects orphaned by force-pushes or
 * deleted branches are dropped; everything gets re-deltified.
 */
async function gcBuild(manifest, plaintextPacks) {
    const scratch = await mkdtemp(join(tmpdir(), 'egit-gc-'));
    // Fresh env: never let a surrounding GIT_DIR point plumbing at another repo.
    const env = { ...process.env };
    delete env.GIT_DIR; delete env.GIT_WORK_TREE; delete env.GIT_INDEX_FILE;
    const gitIn = async (args, opts = {}) => {
        const r = await runGit(args, { cwd: scratch, env, ...opts });
        if (r.code !== 0) throw new Error(`git ${args[0]} failed: ${r.stderr.trim()}`);
        return r;
    };
    try {
        await gitIn(['init', '--bare', '-q', '.']);
        for (const pack of plaintextPacks) {
            await gitIn(['index-pack', '--stdin', '--fix-thin'], { stdin: pack });
        }
        const revs = Object.values(manifest.refs).join('\n') + '\n';
        const r = await gitIn(
            ['pack-objects', '--revs', '--stdout', '--delta-base-offset', '-q'],
            { stdin: revs },
        );
        return new Uint8Array(r.stdout);
    } finally {
        await rm(scratch, { recursive: true, force: true });
    }
}

async function runMaintenance(mode, url) {
    const { base, repoId } = parseRemoteUrl(url ?? '');
    const key = parseKey(process.env.EGIT_KEY);
    const store = makeStoreClient(base, repoId);
    const log = (s) => process.stderr.write(`${s}\n`);

    if (mode === '--compact') {
        const r = await compact(store, key);
        log(`compact ${repoId}: ${r.packsBefore} packs (${r.bytesBefore} B) -> ${r.packsAfter} (${r.bytesAfter} B)`);
    } else if (mode === '--gc') {
        const r = await replacePacks(store, key, gcBuild);
        log(`gc ${repoId}: ${r.packsBefore} packs (${r.bytesBefore} B) -> ${r.packsAfter} (${r.bytesAfter} B)`);
    } else if (mode === '--prune' || mode.startsWith('--prune=')) {
        const mins = Number(mode.split('=')[1] ?? 60);
        if (!Number.isFinite(mins) || mins < 0) throw new Error(`bad --prune age: ${mode}`);
        const r = await pruneOrphans(store, key, { olderThanMs: mins * 60_000 });
        log(`prune ${repoId}: deleted ${r.deleted.length} orphaned pack(s) [${r.deleted.join(', ')}]`);
    } else {
        throw new Error(`unknown maintenance mode: ${mode} (use --compact | --gc | --prune[=mins])`);
    }
}

// ---------------------------------------------------------------------------
// remote-helper protocol loop

async function main() {
    const [, , arg2, url] = process.argv;
    if (arg2?.startsWith('--')) return runMaintenance(arg2, url);

    const { base, repoId } = parseRemoteUrl(url ?? '');
    const key = parseKey(process.env.EGIT_KEY);
    const store = makeStoreClient(base, repoId);
    const out = (s) => process.stdout.write(s);

    const lines = createInterface({ input: process.stdin, terminal: false })[Symbol.asyncIterator]();
    const batch = async (first) => { // a command plus its follow-up lines, blank-terminated
        const cmds = [first];
        for (;;) {
            const { value, done } = await lines.next();
            if (done || value === '') return cmds;
            cmds.push(value);
        }
    };

    for (;;) {
        const { value: line, done } = await lines.next();
        if (done) break;

        if (line === 'capabilities') {
            out('fetch\npush\n\n');
        } else if (line === 'list' || line === 'list for-push') {
            const { manifest } = await loadManifest(store, key);
            out(listRefs(manifest).map(l => `${l}\n`).join('') + '\n');
        } else if (line.startsWith('fetch ')) {
            await batch(line); // wants are implicit: we replay all packs
            await doFetch(store, key);
            out('\n');
        } else if (line.startsWith('push ')) {
            const specs = (await batch(line)).map(l => l.slice('push '.length));
            for (const spec of specs) out(`${await doPush(store, key, spec)}\n`);
            out('\n');
        } else if (line === '') {
            continue;
        } else {
            throw new Error(`unsupported remote-helper command: ${line}`);
        }
    }
}

main().catch((e) => {
    process.stderr.write(`git-remote-egit: ${e.message}\n`);
    process.exit(1);
});
