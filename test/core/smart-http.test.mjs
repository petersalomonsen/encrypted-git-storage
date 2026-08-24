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

    test('a zero-OBJECT pack is a legitimate ref-only push (git force-back) and is accepted', async () => {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(3)), store, KEY);
        // git sends an empty pack when moving a ref to an OID whose objects the
        // server already has (e.g. force-back to an ancestor) — a dumb store
        // cannot connectivity-check that, so it must be allowed through.
        const res = await handleReceivePack(
            pushBody([`${SHA_A} ${SHA_B} refs/heads/master`], fakePack(0, new Uint8Array(0))), store, KEY);
        assert.match(text(res), /ok refs\/heads\/master/);
        assert.equal(store.state.packs.size, 1); // no empty pack stored
        const refs = new TextDecoder().decode((await handleInfoRefs('git-upload-pack', store, KEY)).body);
        assert.match(refs, new RegExp(`${SHA_B} refs/heads/master`));
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

describe('repack: rewrite the packs, move no ref', () => {
    /** A store holding one ref and `packCount` packs, as append-only pushes leave it. */
    async function storeWithPacks(packCount) {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(2)), store, KEY);
        for (let i = 1; i < packCount; i++) {
            await handleReceivePack(pushBody([`${SHA_A} ${SHA_A} refs/heads/master`], fakePack(2, new Uint8Array([i]))), store, KEY);
        }
        return store;
    }
    const currentRefs = async (store) =>
        new TextDecoder().decode((await handleInfoRefs('git-upload-pack', store, KEY)).body);

    test('advertises no refs, so the client packs its whole history', async () => {
        const store = await storeWithPacks(1);
        const normal = new TextDecoder().decode((await handleInfoRefs('git-receive-pack', store, KEY)).body);
        assert.match(normal, new RegExp(`${SHA_A} refs/heads/master`));

        const repack = new TextDecoder().decode(
            (await handleInfoRefs('git-receive-pack', store, KEY, { repack: true })).body);
        assert.doesNotMatch(repack, /refs\/heads\/master/);
        assert.match(repack, /capabilities\^\{\}/);
    });

    test('is a push, so there is nothing to fetch from it', async () => {
        const store = await storeWithPacks(1);
        await assert.rejects(
            () => handleInfoRefs('git-upload-pack', store, KEY, { repack: true }),
            /repack is a push/);
    });

    test('replaces every pack with the one pushed, leaving the ref where it was', async () => {
        const store = await storeWithPacks(3);
        assert.equal(store.state.packs.size, 3);

        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(9, new Uint8Array([9, 9]))),
            store, KEY, { repack: true });
        assert.match(text(res), /ok refs\/heads\/master/);

        // One referenced pack — the new one — and the ref is untouched.
        assert.match(await currentRefs(store), new RegExp(`${SHA_A} refs/heads/master`));
        const served = (await handleUploadPack(concatBytes(pktLines([`want ${SHA_A}\n`, 'done']), FLUSH), store, KEY)).body;
        const dv = new DataView(served.buffer, served.byteOffset + pktLine('NAK\n').length);
        assert.equal(dv.getUint32(8), 9, 'upload-pack now serves only the repacked pack');

        // The superseded packs are still THERE, just unreferenced: pruneOrphans
        // sweeps them later, which is what makes a bad repack recoverable.
        assert.equal(store.state.packs.size, 4);
    });

    test('refuses a tip the store does not currently hold', async () => {
        const store = await storeWithPacks(2);
        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_B} refs/heads/master`], fakePack(9)), store, KEY, { repack: true });
        assert.match(text(res), /ng refs\/heads\/master repack must offer the store's current tip/);
        assert.equal(store.state.packs.size, 2, 'nothing swapped');
        assert.match(await currentRefs(store), new RegExp(`${SHA_A} refs/heads/master`));
    });

    test('refuses to drop a ref it was not offered', async () => {
        const store = await storeWithPacks(1);
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_B} refs/heads/other`], fakePack(2)), store, KEY);
        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(9)), store, KEY, { repack: true });
        assert.match(text(res), /ng refs\/heads\/other repack must cover every ref/);
        assert.match(await currentRefs(store), new RegExp(`${SHA_B} refs/heads/other`));
    });

    test('refuses a repack that carries no pack — that would empty the store', async () => {
        const store = await storeWithPacks(2);
        const res = await handleReceivePack(
            pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], null), store, KEY, { repack: true });
        assert.match(text(res), /ng refs\/heads\/master repack carried no packfile/);
        assert.equal(store.state.packs.size, 2);
    });
});

describe('upload-pack negotiation spanning several POSTs', () => {
    /** A store holding one ref and one pack. */
    async function seeded() {
        const store = memStore();
        await handleReceivePack(pushBody([`${ZEROS} ${SHA_A} refs/heads/master`], fakePack(4)), store, KEY);
        return store;
    }
    const packOf = (res) => {
        const nak = pktLine('NAK\n').length;
        if (res.body.length <= nak) return null;
        const dv = new DataView(res.body.buffer, res.body.byteOffset + nak);
        return { magic: dv.getUint32(0), objects: dv.getUint32(8) };
    };

    test('a first round with wants but no done is NAKed', async () => {
        const store = await seeded();
        const body = concatBytes(pktLines([`want ${SHA_A}\n`, `have ${SHA_B}\n`]), FLUSH);
        const res = await handleUploadPack(body, store, KEY);
        assert.match(text(res), /NAK/);
        assert.equal(packOf(res), null, 'no pack until the client says done');
    });

    test('a CONTINUATION round carries only haves and done — and must still be served', async () => {
        const store = await seeded();
        // Exactly what libgit2 sends once it stops adding wants. Rejecting this
        // for having no wants produced a 500, which git reads as a packfile and
        // reports as "bad packet length".
        const body = concatBytes(pktLines([`have ${SHA_B}\n`]), pktLine('done\n'));
        const res = await handleUploadPack(body, store, KEY);
        const pack = packOf(res);
        assert.ok(pack, 'the continuation round must get the packfile');
        assert.equal(pack.magic, 0x5041434b);
        assert.equal(pack.objects, 4);
    });

    test('done with no haves and no wants is still served (nothing left to negotiate)', async () => {
        const store = await seeded();
        const res = await handleUploadPack(pktLine('done\n'), store, KEY);
        assert.ok(packOf(res), 'done means send it');
    });
});
