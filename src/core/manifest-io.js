// Load/save the encrypted refs manifest through a store client — the one
// (de)crypt + (de)serialize round shared by the remote helper, the smart-HTTP
// handlers and the maintenance ops.
import { encrypt, decrypt } from './crypto.js';
import { emptyManifest, serializeManifest, parseManifest } from './format.js';

/** -> { manifest, etag } (empty manifest + null etag when the repo has no refs yet) */
export async function loadManifest(store, key) {
    const got = await store.getRefs();
    if (!got) return { manifest: emptyManifest(), etag: null };
    return { manifest: parseManifest(await decrypt(key, got.bytes)), etag: got.etag };
}

/** Encrypt a manifest for storage (CAS-write it with store.putRefs(bytes, etag)). */
export function encryptManifest(key, manifest) {
    return encrypt(key, serializeManifest(manifest));
}
