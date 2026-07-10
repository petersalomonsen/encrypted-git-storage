import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
    emptyManifest, serializeManifest, parseManifest,
    nextPackIndex, advanceManifest, packsInOrder, MANIFEST_VERSION,
} from '../../src/core/format.js';

describe('core/format refs manifest', () => {
    test('serialize → parse round-trips', () => {
        const m = advanceManifest(emptyManifest(), {
            refUpdates: { 'refs/heads/main': 'a'.repeat(40) },
            pack: { n: 0, sha: 'f'.repeat(64), size: 1234 },
        });
        assert.deepEqual(parseManifest(serializeManifest(m)), m);
    });

    test('parse rejects unknown versions', () => {
        const bytes = new TextEncoder().encode(JSON.stringify({ version: MANIFEST_VERSION + 1 }));
        assert.throws(() => parseManifest(bytes), /unsupported manifest version/);
    });

    test('advanceManifest updates refs, appends pack, bumps generation — immutably', () => {
        const m0 = emptyManifest();
        const m1 = advanceManifest(m0, {
            refUpdates: { 'refs/heads/main': '1'.repeat(40) },
            pack: { n: 0, sha: 'a'.repeat(64), size: 10 },
        });
        const m2 = advanceManifest(m1, {
            refUpdates: { 'refs/heads/main': '2'.repeat(40), 'refs/heads/dev': '3'.repeat(40) },
            pack: { n: nextPackIndex(m1), sha: 'b'.repeat(64), size: 20 },
        });

        assert.equal(m0.generation, 0, 'input not mutated');
        assert.deepEqual(m0.refs, {});
        assert.equal(m2.generation, 2);
        assert.equal(m2.refs['refs/heads/main'], '2'.repeat(40));
        assert.equal(m2.packs.length, 2);
        assert.equal(nextPackIndex(m2), 2);

        // ref deletion via null
        const m3 = advanceManifest(m2, { refUpdates: { 'refs/heads/dev': null } });
        assert.deepEqual(Object.keys(m3.refs), ['refs/heads/main']);
        assert.equal(m3.packs.length, 2, 'ref-only update appends no pack');
    });

    test('packsInOrder sorts by index without mutating', () => {
        const m = { ...emptyManifest(), packs: [{ n: 2 }, { n: 0 }, { n: 1 }] };
        assert.deepEqual(packsInOrder(m).map(p => p.n), [0, 1, 2]);
        assert.deepEqual(m.packs.map(p => p.n), [2, 0, 1]);
    });
});
