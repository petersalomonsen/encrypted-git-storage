// AES-256-GCM encrypt/decrypt for packfiles and the refs manifest.
//
// Uses WebCrypto (globalThis.crypto.subtle), available in Node 20+, the browser,
// and service workers — so the same code runs in the SW and the CLI remote helper.
//
// Output framing (so any consumer can parse without side channels):
//   [ 4 bytes magic "EGS1" ][ 12-byte random IV ][ AES-GCM ciphertext+tag ]
//
// The key is a 32-byte (256-bit) secret held only by the client. In Ariz it is
// derived from a fixed-nonce NEP-413 wallet signature via HKDF (done in the app,
// not here); this module just takes the raw key bytes.

const MAGIC = new Uint8Array([0x45, 0x47, 0x53, 0x31]); // "EGS1"
const IV_LEN = 12;

async function importKey(keyBytes) {
    if (keyBytes?.byteLength !== 32) {
        throw new Error(`key must be 32 bytes, got ${keyBytes?.byteLength}`);
    }
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Encrypt bytes → framed Uint8Array. */
export async function encrypt(keyBytes, plaintext) {
    const key = await importKey(keyBytes);
    const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext));
    const out = new Uint8Array(MAGIC.length + IV_LEN + ct.length);
    out.set(MAGIC, 0);
    out.set(iv, MAGIC.length);
    out.set(ct, MAGIC.length + IV_LEN);
    return out;
}

/** Decrypt a framed Uint8Array → plaintext Uint8Array. Throws on tamper/wrong key. */
export async function decrypt(keyBytes, framed) {
    const buf = new Uint8Array(framed);
    for (let i = 0; i < MAGIC.length; i++) {
        if (buf[i] !== MAGIC[i]) throw new Error('bad magic — not an EGS1 blob');
    }
    const iv = buf.subarray(MAGIC.length, MAGIC.length + IV_LEN);
    const ct = buf.subarray(MAGIC.length + IV_LEN);
    const key = await importKey(keyBytes);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

/** True if `bytes` looks like one of our encrypted blobs (used by the ciphertext assertion). */
export function isEncrypted(bytes) {
    const b = new Uint8Array(bytes);
    return b.length >= MAGIC.length && MAGIC.every((m, i) => b[i] === m);
}

/** SHA-256 as lowercase hex — used for plaintext-pack identities in the manifest. */
export async function sha256hex(bytes) {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}
