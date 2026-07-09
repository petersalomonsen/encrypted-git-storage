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
// TODO(next session):
//  - serializeManifest(manifest) -> Uint8Array   (JSON is fine to start)
//  - parseManifest(Uint8Array)   -> manifest
//  - helpers to add a pack, advance a ref, bump generation
//  - keep this backend- and env-agnostic (no Node/browser-only APIs)

export const MANIFEST_VERSION = 1;

export function emptyManifest() {
    return { version: MANIFEST_VERSION, refs: {}, packs: [], generation: 0 };
}

export function serializeManifest(manifest) {
    return new TextEncoder().encode(JSON.stringify(manifest));
}

export function parseManifest(bytes) {
    return JSON.parse(new TextDecoder().decode(bytes));
}
