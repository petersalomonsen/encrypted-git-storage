// Encrypted-store format: the refs manifest and the pack index/layout that both
// the service worker and the CLI remote helper read/write.
//
// Store layout (object keys, per opaque <repoId>):
//   <repoId>/packs/<n>   encrypted packfile (append-only; one per push)
//   <repoId>/refs        encrypted refs manifest (below), updated via CAS
//
// Refs manifest (plaintext shape, before encrypt() from ../core/crypto.js):
//   {
//     version: 1,
//     refs: { "refs/heads/main": "<sha>", ... },
//     packs: [{ n: 0, sha: "<hash-of-plaintext-pack>", size: <int> }, ...],
//     generation: <int>   // bumped each push; used for compare-and-set
//   }
//
// Backend- and env-agnostic: shared verbatim by the service worker and the CLI
// remote helper (no Node/browser-only APIs).

export const MANIFEST_VERSION = 1;

export function emptyManifest() {
    return { version: MANIFEST_VERSION, refs: {}, packs: [], generation: 0 };
}

export function serializeManifest(manifest) {
    return new TextEncoder().encode(JSON.stringify(manifest));
}

export function parseManifest(bytes) {
    const manifest = JSON.parse(new TextDecoder().decode(bytes));
    if (manifest.version !== MANIFEST_VERSION) {
        throw new Error(`unsupported manifest version ${manifest.version} (expected ${MANIFEST_VERSION})`);
    }
    return manifest;
}

/** First free pack index (packs are append-only, one per push). */
export function nextPackIndex(manifest) {
    return manifest.packs.reduce((max, p) => Math.max(max, p.n + 1), 0);
}

/**
 * One push applied to a manifest → a NEW manifest with `generation` bumped.
 *  - refUpdates: { "<refname>": "<sha>" | null }  (null deletes the ref)
 *  - pack:       { n, sha, size } | null          (null for ref-only updates)
 */
export function advanceManifest(manifest, { refUpdates = {}, pack = null } = {}) {
    const refs = { ...manifest.refs };
    for (const [name, sha] of Object.entries(refUpdates)) {
        if (sha === null) delete refs[name];
        else refs[name] = sha;
    }
    const packs = pack ? [...manifest.packs, pack] : [...manifest.packs];
    return { version: MANIFEST_VERSION, refs, packs, generation: manifest.generation + 1 };
}

/** Packs sorted by index — the order fetch must replay them (thin-pack bases). */
export function packsInOrder(manifest) {
    return [...manifest.packs].sort((a, b) => a.n - b.n);
}
