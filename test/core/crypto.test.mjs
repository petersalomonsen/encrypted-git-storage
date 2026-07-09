import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { encrypt, decrypt, isEncrypted } from '../../src/core/crypto.js';

const key = () => crypto.getRandomValues(new Uint8Array(32));

describe('core/crypto AES-256-GCM', () => {
    test('round-trips arbitrary bytes', async () => {
        const k = key();
        const pt = crypto.getRandomValues(new Uint8Array(5000)); // stand-in for a packfile
        const blob = await encrypt(k, pt);
        assert.ok(isEncrypted(blob), 'framed output is recognizable');
        assert.deepEqual(await decrypt(k, blob), pt);
    });

    test('ciphertext does not contain the plaintext (zero-knowledge)', async () => {
        const k = key();
        const pt = new TextEncoder().encode('PACK\x00\x00\x00\x02 secret git objects');
        const blob = await encrypt(k, pt);
        // The store must never see plaintext; the blob must not start with "PACK".
        assert.ok(!isPack(blob));
        assert.equal(indexOf(blob, pt), -1);
    });

    test('wrong key fails to decrypt', async () => {
        const blob = await encrypt(key(), new Uint8Array([1, 2, 3]));
        await assert.rejects(() => decrypt(key(), blob));
    });

    test('tampering is detected (GCM auth tag)', async () => {
        const k = key();
        const blob = await encrypt(k, new Uint8Array([1, 2, 3, 4]));
        blob[blob.length - 1] ^= 0xff; // flip a ciphertext byte
        await assert.rejects(() => decrypt(k, blob));
    });
});

function isPack(bytes) {
    const b = new Uint8Array(bytes);
    return b[0] === 0x50 && b[1] === 0x41 && b[2] === 0x43 && b[3] === 0x4b; // "PACK"
}
function indexOf(hay, needle) {
    const h = new Uint8Array(hay), n = new Uint8Array(needle);
    outer: for (let i = 0; i <= h.length - n.length; i++) {
        for (let j = 0; j < n.length; j++) if (h[i + j] !== n[j]) continue outer;
        return i;
    }
    return -1;
}
