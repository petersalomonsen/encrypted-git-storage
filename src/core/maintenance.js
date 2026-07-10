// Store maintenance: pack compaction and orphan pruning.
//
// The append model (one encrypted pack per push) grows without bound, and a
// pusher that stores a pack but then loses the refs CAS leaves an orphaned
// `packs/<n>` object behind. These ops fix both — client-side, so the backend
// still only ever sees ciphertext:
//
//  - compact(): merge every referenced pack into ONE (core/packcat.js — no git
//    needed, so this also runs in the browser). Keeps all objects, including
//    unreachable ones; it shrinks pack COUNT and per-object overhead only.
//  - replacePacks(build): the CAS-safe swap loop compact() is built on. A CLI
//    with real git can pass a reachability-aware builder instead (the remote
//    helper's --gc does: replay packs into a scratch repo, `git pack-objects`
//    from the manifest refs — dropping objects orphaned by force-pushes).
//  - pruneOrphans(): delete stored packs the manifest doesn't reference. Age-
//    guarded (store lastModified) so a concurrent pusher's freshly stored pack
//    is never swept before its refs-CAS lands.
//
// Concurrency: replacePacks CAS-writes the manifest, so it can never lose a
// racing push — one of the two retries. Superseded packs are deleted only
// AFTER the CAS wins; a reader holding the old manifest can hit a deleted
// pack (GET 404) — it must reload the manifest and retry (readers of the new
// manifest never reference deleted packs).

import { encrypt, decrypt, sha256hex } from './crypto.js';
import { MANIFEST_VERSION, nextPackIndex, packsInOrder } from './format.js';
import { loadManifest, encryptManifest } from './manifest-io.js';
import { concatPacks, packObjectCount } from './packcat.js';

/**
 * Replace ALL referenced packs with one rebuilt pack, without losing concurrent
 * pushes (refs CAS; retries with a fresh manifest on conflict).
 * `build(manifest, plaintextPacks)` -> merged plaintext pack (Uint8Array).
 */
export async function replacePacks(store, key, build, { attempts = 3 } = {}) {
    for (let attempt = 0; attempt < attempts; attempt++) {
        const { manifest, etag } = await loadManifest(store, key);
        if (manifest.packs.length === 0) {
            return { packsBefore: 0, packsAfter: 0, bytesBefore: 0, bytesAfter: 0 };
        }
        const bytesBefore = manifest.packs.reduce((n, p) => n + p.size, 0);

        const plaintextPacks = [];
        for (const p of packsInOrder(manifest)) {
            const pack = await decrypt(key, await store.getPack(p.n));
            if (packObjectCount(pack) > 0) plaintextPacks.push(pack);
        }
        const merged = await build(manifest, plaintextPacks);

        let n = nextPackIndex(manifest);
        const encrypted = await encrypt(key, merged);
        while (!(await store.putPack(n, encrypted))) n++;

        const next = {
            version: MANIFEST_VERSION,
            refs: manifest.refs,
            packs: [{ n, sha: await sha256hex(merged), size: merged.length }],
            generation: manifest.generation + 1,
        };
        if (await store.putRefs(await encryptManifest(key, next), etag)) {
            for (const p of manifest.packs) await store.deletePack(p.n).catch(() => {});
            return { packsBefore: manifest.packs.length, packsAfter: 1, bytesBefore, bytesAfter: merged.length, n };
        }
        // CAS lost to a concurrent push — remove our (still unreferenced) pack
        // and retry against the fresh manifest.
        await store.deletePack(n).catch(() => {});
    }
    throw new Error('replacePacks: refs CAS kept failing (busy repo?) — try again');
}

/** Merge every pack into one. Env-agnostic (runs in the browser too). */
export async function compact(store, key) {
    const { manifest } = await loadManifest(store, key);
    if (manifest.packs.length <= 1) {
        const size = manifest.packs[0]?.size ?? 0;
        return { packsBefore: manifest.packs.length, packsAfter: manifest.packs.length, bytesBefore: size, bytesAfter: size };
    }
    return replacePacks(store, key, (_manifest, packs) => concatPacks(packs));
}

/**
 * Delete stored packs the manifest does not reference (lost-CAS leftovers,
 * interrupted compactions). Only touches packs older than `olderThanMs` so a
 * pack stored by an in-flight push (CAS not yet landed) is never swept.
 */
export async function pruneOrphans(store, key, { olderThanMs = 60 * 60_000, now = Date.now() } = {}) {
    const { manifest } = await loadManifest(store, key);
    const referenced = new Set(manifest.packs.map(p => p.n));
    const deleted = [];
    for (const p of await store.listPacks()) {
        if (!referenced.has(p.n) && p.lastModified <= now - olderThanMs) {
            await store.deletePack(p.n);
            deleted.push(p.n);
        }
    }
    return { deleted };
}
