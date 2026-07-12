// Unit tests for the smart-HTTP handlers against an in-memory store — no MinIO,
// no git binary: drives handleReceivePack/handleInfoRefs/handleUploadPack with
// hand-framed pkt-lines and minimal packs (the store treats packs as opaque
// bytes; only the 12-byte header's object count is inspected).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { handleInfoRefs, handleUploadPack, handleReceivePack } from '../../src/core/smart-http.js';
import { pktLine, pktLines, concatBytes, FLUSH } from '../../src/core/pktline.js';

const KEY = Uint8Array.from({ length: 32 }, (_, i) => i);
const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const ZEROS = '0'.repeat(40);

function memStore() {
    const state = { refs: null, etag: 0, packs: new Map() };
    return {
        state,
        async getRefs() {
            return state.refs ? { bytes: state.refs, etag: `"v${state.etag}"` } : null;
        },
        async putRefs(bytes, etag) {
            if (etag === null && state.refs) return false;
            if (etag !== null && etag !== `"v${state.etag}"`) return false;
            state.refs = bytes; state.etag++;
            return true;
        },
        async getPack(n) { return state.packs.get(n); },
        async putPack(n, bytes) {
            if (state.packs.has(n)) return false;
            state.packs.set(n, bytes);
            return true;
        },
        async listPacks() {
            return [...state.packs.entries()].map(([n, b]) => ({ n, size: b.length, lastModified: 0 }));
        },
        async deletePack(n) { state.packs.delete(n); },
    };
}

/** A minimal "pack": valid header claiming `count` objects + body + trailer. */
function fakePack(count, body = new Uint8Array([1, 2, 3])) {
    const out = new Uint8Array(12 + body.length + 20);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, 0x5041434b); // PACK
    dv.setUint32(4, 2);
    dv.setUint32(8, count);
    out.set(body, 12);
    return out;
}

const pushBody = (commands, pack) => concatBytes(
    pktLines(commands.map((c, i) => i === 0 ? `${c}\0report-status\n` : `${c}\n`)),
    pack ?? new Uint8Array(0),
);

const text = (res) => new TextDecoder().decode(res.body);

describe('receive-pack: pack-less pushes must not lose objects', () => {
    test('a normal push with a pack updates the ref and stores the pack', async () => {
        const store = memStore();
        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        assert.match(text(res), /unpack ok/);
        assert.match(text(res), /ok refs\/heads\/master/);
        assert.equal(store.state.packs.size, 1);

        const refs = await handleInfoRefs('git-upload-pack', store, KEY);
        assert.match(new TextDecoder().decode(refs.body), new RegExp(`${SHA_A} refs/heads/master`));
    });

    test('REJECTS a pack-less push that moves a ref to an unknown OID', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);

        // The failure mode observed in production: ref would advance to SHA_B
        // while no objects for it exist anywhere in the store.
        const res = await handleReceivePack(
            pushBody([`${SHA_A} ${SHA_B} refs/heads/master`]), store, KEY);
        assert.match(text(res), /ng refs\/heads\/master push carried no packfile/);

        // Ref must still be at SHA_A.
        const refs = new TextDecoder().decode((await handleInfoRefs('git-upload-pack', store, KEY)).body);
        assert.match(refs, new RegExp(`${SHA_A} refs/heads/master`));
        assert.doesNotMatch(refs, new RegExp(SHA_B));
    });

    test('a zero-object pack is treated as pack-less and rejected the same way', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        const res = await handleReceivePack(
            pushBody([`${SHA_A} ${SHA_B} refs/heads/master`], fakePack(0, new Uint8Array(0))), store, KEY);
        assert.match(text(res), /ng refs\/heads\/master push carried no packfile/);
    });

    test('pack-less ref DELETE is allowed', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        const res = await handleReceivePack(
            pushBody([`${SHA_A} ${ZEROS} refs/heads/master`]), store, KEY);
        assert.match(text(res), /ok refs\/heads\/master/);
    });

    test('pack-less branch creation at an EXISTING ref OID is allowed', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_A} refs/heads/backup`]), store, KEY);
        assert.match(text(res), /ok refs\/heads\/backup/);
    });

    test('a flush-only PROBE request (remote-curl, >1MiB pushes) gets an empty 200, not an error', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        // git's remote-curl sends exactly one flush pkt to probe before
        // streaming a large push body; the real push follows separately.
        const res = await handleReceivePack(new TextEncoder().encode('0000'), store, KEY);
        assert.equal(res.body.length, 0);
        assert.equal(res.contentType, 'application/x-git-receive-pack-result');
        // Nothing changed: no pack stored, ref untouched.
        assert.equal(store.state.packs.size, 1);
        const refs = new TextDecoder().decode((await handleInfoRefs('git-upload-pack', store, KEY)).body);
        assert.match(refs, new RegExp(`${SHA_A} refs/heads/master`));
    });

    test('upload-pack serves the stored packs merged after a push', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(2)), store, KEY);
        const body = pktLines(['want ' + SHA_A + '\n', 'done']);
        const res = await handleUploadPack(concatBytes(body, FLUSH), store, KEY);
        const out = res.body;
        // response = NAK pkt + merged pack (header count preserved)
        const nakLen = pktLine('NAK\n').length;
        const dv = new DataView(out.buffer, out.byteOffset + nakLen);
        assert.equal(dv.getUint32(0), 0x5041434b);
        assert.equal(dv.getUint32(8), 2);
    });
});
