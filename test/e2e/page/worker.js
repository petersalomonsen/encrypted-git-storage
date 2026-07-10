// Module worker driving wasm-git for the e2e tests. All git traffic goes over
// smart HTTP to /egit/<repoId>/… — intercepted by the service worker, which
// serves it from the encrypted object store.
//
// Ops are invoked from the page via postMessage {id, op, args} → {id, result|error}.
import { loadOpfsGit } from '/node_modules/wasm-git/lg2_opfs_auto.js';
import { compact } from '/src/core/maintenance.js';
import { makeStoreClient } from '/src/core/store-client.js';

let gitPromise = null;
const git = () => (gitPromise ??= loadOpfsGit({ user: 'Browser Test', email: 'browser@example.com' }));

// Deterministic pseudo-random bytes (xorshift32) — the node side generates the
// same bytes to verify binary round-trips without shipping blobs around.
function noise(len, seed) {
    const out = new Uint8Array(len);
    let s = seed >>> 0 || 1;
    for (let i = 0; i < len; i++) {
        s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0;
        out[i] = s & 0xff;
    }
    return out;
}

const ops = {
    async variant() {
        return (await git()).variant;
    },

    async clone({ url, repoName }) {
        const g = await git();
        await g.clone(url, repoName);
        return g.readdir(repoName);
    },

    async writeFile({ repoName, filename, contents }) {
        const g = await git();
        await g.writeFile(repoName, filename, contents);
    },

    async writeNoise({ repoName, filename, size, seed }) {
        const g = await git();
        await g.writeFile(repoName, filename, noise(size, seed));
    },

    async readFile({ repoName, filename, encoding = 'utf8' }) {
        const g = await git();
        const data = g.readFile(repoName, filename, encoding === 'utf8' ? 'utf8' : 'binary');
        return encoding === 'utf8' ? data : Array.from(data);
    },

    // sha256 of a working-tree file — lets specs verify big binaries cheaply
    async hashFile({ repoName, filename }) {
        const g = await git();
        const data = g.readFile(repoName, filename, 'binary');
        const digest = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
    },

    async addCommitPush({ repoName, filename, message }) {
        const g = await git();
        await g.addCommitPush(repoName, filename, message);
    },

    async readdir({ repoName }) {
        return (await git()).readdir(repoName);
    },

    async removeRepo({ repoName }) {
        await (await git()).removeRepo(repoName);
    },

    // Store compaction straight from the browser — env-agnostic core code
    // talking to the gateway; the key stays client-side, as always.
    async compact({ repoId, keyHex }) {
        const key = Uint8Array.from(keyHex.match(/../g), h => parseInt(h, 16));
        const store = makeStoreClient(`${self.location.origin}/store/${repoId}`, repoId);
        return compact(store, key);
    },

    // escape hatch: run any lg2 command inside a repo (fetch, merge, checkout…)
    async run({ repoName, args }) {
        const g = await git();
        g.FS.chdir(g.repoDir(repoName));
        await g.run(args);
        g.FS.chdir(g.repoDir(repoName));
    },
};

onmessage = async (e) => {
    const { id, op, args } = e.data;
    try {
        if (!ops[op]) throw new Error(`unknown op: ${op}`);
        postMessage({ id, result: (await ops[op](args)) ?? null });
    } catch (err) {
        postMessage({ id, error: String(err?.stack ?? err) });
    }
};
