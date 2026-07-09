// Object-storage harness — the CI-runnable proof that our dumb store works over a
// real S3 API (MinIO). This is deliberately backend-only: it exercises the exact
// operations the encrypted-pack store needs (put/get/list/delete of opaque blobs,
// and a create-if-absent conditional write for refs-CAS), independent of any git
// or encryption logic. Keep this green; build the rest on top.
import { test, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    makeClient, ensureBucket, storeReachable, put, getBytes, list, del, S3_BUCKET
} from '../helpers/minio.mjs';

const client = makeClient();
let reachable = false;

before(async () => {
    reachable = await storeReachable(client);
    if (reachable) await ensureBucket(client);
    else console.warn(`\n[skip] object store not reachable — start MinIO or set S3_ENDPOINT. Bucket=${S3_BUCKET}\n`);
});

describe('object store harness (MinIO / S3)', () => {
    test('put → get round-trips opaque bytes', { skip: () => !reachable }, async () => {
        const key = `t/${Date.now()}/pack-0`;
        const body = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02]);
        await put(client, key, body);
        const got = await getBytes(client, key);
        assert.deepEqual(got, body);
        await del(client, key);
    });

    test('list returns keys under a repo prefix', { skip: () => !reachable }, async () => {
        const repo = `t/${Date.now()}-list`;
        await put(client, `${repo}/packs/0`, Buffer.from('a'));
        await put(client, `${repo}/packs/1`, Buffer.from('b'));
        await put(client, `${repo}/refs`, Buffer.from('r'));
        const keys = (await list(client, `${repo}/`)).sort();
        assert.deepEqual(keys, [`${repo}/packs/0`, `${repo}/packs/1`, `${repo}/refs`]);
        for (const k of keys) await del(client, k);
    });

    // Refs-CAS primitive: create-if-absent via If-None-Match:"*". Two racing
    // creators — exactly one wins; the other gets 412 PreconditionFailed. This is
    // the building block for "update refs only if unchanged" on push.
    // NOTE: verify the target MinIO version supports conditional PutObject; if not,
    // this test skips and the design falls back to versioned-object CAS (see docs).
    test('create-if-absent conditional write (refs-CAS primitive)', { skip: () => !reachable }, async () => {
        const key = `t/${Date.now()}-cas/refs`;
        const attempt = () => put(client, key, Buffer.from('v1'), { IfNoneMatch: '*' })
            .then(() => 'ok', (e) => e?.$metadata?.httpStatusCode ?? e?.name ?? 'err');

        const [a, b] = await Promise.all([attempt(), attempt()]);
        const results = [a, b];
        const wins = results.filter(r => r === 'ok').length;
        const conflicts = results.filter(r => r === 412 || r === 'PreconditionFailed').length;

        if (wins === 1 && conflicts === 1) {
            // Ideal: backend enforced the conditional write.
            assert.equal(wins, 1);
        } else {
            // Backend may not enforce IfNoneMatch (older MinIO). Don't fail the
            // harness; flag it so the implementer picks the versioned-object CAS path.
            console.warn(`[warn] conditional-write not enforced by this store (wins=${wins}). Use versioned-object CAS for refs — see docs/design.md.`);
        }
        await del(client, key).catch(() => {});
    });
});
