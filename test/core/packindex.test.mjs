import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { deflateSync, constants as Z } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inflateAt, applyDelta, parsePack, indexPacks } from '../../src/core/packindex.js';
import { concatPacks, mergePacks, packObjectCount } from '../../src/core/packcat.js';

const execFileP = promisify(execFile);

// Deterministic bytes: some compressible (text), some not (noise).
function noise(len, seed) {
    const out = new Uint8Array(len);
    let s = seed >>> 0 || 1;
    for (let i = 0; i < len; i++) { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; out[i] = s & 0xff; }
    return out;
}
const text = (lines, seed) => {
    const words = ['near', 'price', 'usd', 'nok', '2026', 'account', '{', '}', '"', ':', ',', '\n'];
    const r = noise(lines * 8, seed);
    let s = '';
    for (let i = 0; i < r.length; i++) s += words[r[i] % words.length] + (i % 8 === 7 ? '\n' : ' ');
    return new TextEncoder().encode(s);
};

describe('core/packindex inflate', () => {
    const cases = [
        ['empty', new Uint8Array(0)],
        ['one byte', new Uint8Array([7])],
        ['text', text(2000, 3)],
        ['noise (stored blocks)', noise(200_000, 5)],
        ['long runs', new Uint8Array(300_000).fill(65)],
        ['mixed', new Uint8Array([...text(500, 9), ...noise(70_000, 11), ...text(500, 13)])],
    ];
    for (const [name, data] of cases) {
        for (const level of [0, 1, 6, 9]) {
            for (const strategy of [Z.Z_DEFAULT_STRATEGY, Z.Z_FIXED, Z.Z_HUFFMAN_ONLY, Z.Z_RLE]) {
                test(`${name}, level ${level}, strategy ${strategy}: content and exact end`, () => {
                    const z = deflateSync(data, { level, strategy });
                    // Junk after the stream must not be consumed: the end
                    // offset is where the next pack object starts.
                    const buf = new Uint8Array([9, 9, 9, ...z, 0xde, 0xad, 0xbe, 0xef]);
                    const { data: out, end } = inflateAt(buf, 3, data.length);
                    assert.deepEqual(out, data);
                    assert.equal(end, 3 + z.length);
                });
            }
        }
    }

    test('a stream whose declared size is wrong is refused', () => {
        const data = text(100, 1);
        const z = deflateSync(data);
        assert.throws(() => inflateAt(z, 0, data.length - 1), /declared size/);
        assert.throws(() => inflateAt(z, 0, data.length + 1), /inflated to/);
    });

    test('a stream cut short is refused', () => {
        const data = noise(5000, 1);
        const z = deflateSync(data, { level: 0 });
        assert.throws(() => inflateAt(z.subarray(0, z.length - 10), 0, data.length));
    });
});

describe('core/packindex delta', () => {
    test('copy and insert opcodes', () => {
        const base = new TextEncoder().encode('hello, world');
        // src 12, dst 11: copy "hello" (off 0 len 5), insert " there"
        const delta = new Uint8Array([12, 11, 0x80 | 0x01 | 0x10, 0, 5, 6, ...new TextEncoder().encode(' there')]);
        assert.equal(new TextDecoder().decode(applyDelta(base, delta)), 'hello there');
    });
    test('a delta for a different base size is refused', () => {
        assert.throws(() => applyDelta(new Uint8Array(3), new Uint8Array([4, 1, 1, 65])), /4-byte base/);
    });
});

describe('core/packindex against real git', () => {
    let work, env;
    const git = (cwd, ...args) => execFileP('git', args, { cwd, env, maxBuffer: 1 << 28 });
    const run = (cwd, args, stdin) => new Promise((resolve, reject) => {
        const child = spawn('git', args, { cwd, env });
        const out = [], err = [];
        child.stdout.on('data', (c) => out.push(c));
        child.stderr.on('data', (c) => err.push(c));
        child.on('close', (code) => code === 0
            ? resolve(new Uint8Array(Buffer.concat(out)))
            : reject(new Error(`git ${args[0]} exited ${code}: ${Buffer.concat(err)}`)));
        child.stdin.end(stdin);
    });
    // What a push sends: thin, deltas by offset, only what `^old` does not hold.
    const pushPack = (repo, revs) => run(repo, ['pack-objects', '--revs', '--thin', '--stdout', '--delta-base-offset', '-q'], revs);
    const sha = async (repo, rev) => (await git(repo, 'rev-parse', rev)).stdout.trim();

    // The objects git itself finds in a pack, by offset. Indexed inside the
    // source repo so a thin pack's bases are at hand (--fix-thin appends them
    // after the pack's own records, so those offsets do not move).
    async function gitIndex(pack) {
        const out = new TextDecoder().decode(await run(repo, ['index-pack', '--stdin', '--fix-thin'], pack));
        const hash = out.trim().split(/\s+/).pop();
        const idx = await readFile(join(repo, '.git', 'objects', 'pack', `pack-${hash}.idx`));
        return new TextDecoder().decode(await run(repo, ['show-index', '--object-format=sha1'], idx));
    }

    // A strictly valid pack, holding every object of `tips`, in an otherwise empty repo.
    async function assertCompletePack(pack, tips, name) {
        const dir = join(work, `check-${name}`);
        await git(work, 'init', '-q', '--bare', dir);
        await run(dir, ['index-pack', '--stdin', '--strict'], pack);
        for (const tip of tips) await git(dir, 'update-ref', `refs/heads/t-${tip.slice(0, 7)}`, tip);
        await git(dir, 'fsck', '--full', '--strict', '--no-dangling');
        return dir;
    }

    let repo, A, B, C, D;
    before(async () => {
        work = await mkdtemp(join(tmpdir(), 'packindex-'));
        env = { ...process.env, GIT_AUTHOR_NAME: 'T', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 'T', GIT_COMMITTER_EMAIL: 't@t' };
        repo = join(work, 'repo');
        await mkdir(join(repo, 'prices', 'NEAR'), { recursive: true });
        await git(repo, 'init', '-q', '-b', 'master');
        const v1 = text(3000, 1);
        // A: the original prices (big, delta-friendly) and a binary
        await writeFile(join(repo, 'prices', 'NEAR', 'usd.json'), v1);
        await writeFile(join(repo, 'prices', 'NEAR', 'nok.json'), text(500, 2));
        await writeFile(join(repo, 'blob.bin'), noise(50_000, 3));
        await git(repo, 'add', '.');
        await git(repo, 'commit', '-q', '-m', 'A');
        A = await sha(repo, 'HEAD');
        // B: another device's merge rewrote the file
        await writeFile(join(repo, 'prices', 'NEAR', 'usd.json'), new Uint8Array([...v1, ...text(50, 4)]));
        await git(repo, 'commit', '-q', '-am', 'B');
        B = await sha(repo, 'HEAD');
        // C: the file is back to exactly what A had, plus an unrelated change
        await writeFile(join(repo, 'prices', 'NEAR', 'usd.json'), v1);
        await writeFile(join(repo, 'other.json'), text(10, 5));
        await git(repo, 'add', '.');
        await git(repo, 'commit', '-q', '-m', 'C');
        C = await sha(repo, 'HEAD');
        // D: ordinary growth
        await writeFile(join(repo, 'prices', 'NEAR', 'nok.json'), new Uint8Array([...text(500, 2), ...text(20, 6)]));
        await git(repo, 'commit', '-q', '-am', 'D');
        D = await sha(repo, 'HEAD');
    });
    after(() => rm(work, { recursive: true, force: true }));

    test('object ids match git index-pack, for full and thin packs, OFS and REF deltas', async () => {
        const packs = [
            await pushPack(repo, `${A}\n`),
            await pushPack(repo, `${B}\n^${A}\n`),
            await pushPack(repo, `${D}\n^${B}\n`),
            // no --delta-base-offset: every delta is a REF_DELTA
            await run(repo, ['pack-objects', '--revs', '--stdout', '-q'], `${D}\n`),
        ];
        const indexed = await indexPacks([packs[0], packs[1], packs[2]]);
        const [indexedRef] = await indexPacks([packs[3]]);
        const types = new Set();
        for (const [i, entries] of [...indexed, indexedRef].entries()) {
            const pack = i < 3 ? packs[i] : packs[3];
            const truth = new Map((await gitIndex(pack)).trim().split('\n')
                .map((l) => l.split(' ')).map(([off, oid]) => [Number(off), oid]));
            assert.equal(entries.length, packObjectCount(pack));
            for (const e of entries) {
                assert.equal(e.oid, truth.get(e.start), `pack ${i} offset ${e.start}`);
                types.add(e.type);
            }
        }
        // The fixture must really exercise both delta kinds.
        assert.ok(types.has(6), 'an OFS_DELTA was indexed');
        assert.ok(types.has(7), 'a REF_DELTA was indexed');
    });

    test('a plain commit that restores older content re-sends objects the store holds — and mergePacks serves them once', async () => {
        // Exactly the pushes the store kept: one pack per push, each built
        // against the remote tip only.
        const packs = [
            await pushPack(repo, `${A}\n`),
            await pushPack(repo, `${B}\n^${A}\n`),
            await pushPack(repo, `${C}\n^${B}\n`),
            await pushPack(repo, `${D}\n^${C}\n`),
        ];
        const oids = (await indexPacks(packs)).flat().map((e) => e.oid);
        const distinct = new Set(oids).size;
        assert.ok(oids.length > distinct, 'the C push re-sent objects A already stored (the bug this guards against)');

        // concatPacks reproduces what a store used to serve: git refuses it.
        const concat = await concatPacks(packs);
        await assert.rejects(() => assertCompletePack(concat, [D], 'concat'), /twice|duplicate/i);

        const merged = await mergePacks(packs);
        assert.equal(packObjectCount(merged), distinct);
        assert.equal(merged.dropped, oids.length - distinct);
        const dir = await assertCompletePack(merged, [D], 'merged');
        // Every commit and its tree is there, and the restored file reads back.
        for (const c of [A, B, C, D]) await git(dir, 'cat-file', '-e', `${c}^{tree}`);
        const restored = (await git(dir, 'cat-file', 'blob', `${C}:prices/NEAR/usd.json`)).stdout;
        assert.equal(restored, (await git(repo, 'cat-file', 'blob', `${A}:prices/NEAR/usd.json`)).stdout);
    });

    test('an OFS_DELTA based on a dropped copy, or spanning a dropped record, is rewritten and still resolves', async () => {
        // pack 1 holds X. pack 2 holds X again, Y (a delta against X by
        // offset) and Z, with Z after the gap — built from an explicit object
        // list so git deltifies inside pack 2.
        const big = text(4000, 21);
        const x = join(work, 'x.txt'), y = join(work, 'y.txt'), z = join(work, 'z.txt');
        await writeFile(x, big);
        await writeFile(y, new Uint8Array([...big, ...text(30, 22)]));
        await writeFile(z, new Uint8Array([...big.subarray(0, 20000), ...text(40, 23)]));
        const X = (await git(repo, 'hash-object', '-w', x)).stdout.trim();
        const Y = (await git(repo, 'hash-object', '-w', y)).stdout.trim();
        const Z = (await git(repo, 'hash-object', '-w', z)).stdout.trim();
        const pack1 = await run(repo, ['pack-objects', '--stdout', '-q'], `${X}\n`);
        const pack2 = await run(repo, ['pack-objects', '--stdout', '--delta-base-offset', '-q'], `${X}\n${Y}\n${Z}\n`);
        const p2 = parsePack(pack2);
        assert.ok(p2.some((e) => e.type === 6), 'pack 2 really has an OFS_DELTA');

        const merged = await mergePacks([pack1, pack2]);
        assert.equal(merged.dropped, 1);
        assert.equal(packObjectCount(merged), 3);
        const dir = join(work, 'ofs-check');
        await git(work, 'init', '-q', '--bare', dir);
        await run(dir, ['index-pack', '--stdin', '--strict'], merged);
        for (const [oid, file] of [[X, x], [Y, y], [Z, z]]) {
            const got = await run(dir, ['cat-file', 'blob', oid], '');
            assert.deepEqual(Buffer.from(got), await readFile(file), `content of ${oid}`);
        }
        // And the merged pack indexes back to the same three ids.
        const [again] = await indexPacks([merged]);
        assert.deepEqual(new Set(again.map((e) => e.oid)), new Set([X, Y, Z]));
    });

    test('packs without duplicates are passed through byte for byte', async () => {
        const packs = [await pushPack(repo, `${A}\n`), await pushPack(repo, `${B}\n^${A}\n`)];
        const merged = await mergePacks(packs);
        assert.equal(merged.dropped, 0);
        assert.deepEqual(Buffer.from(merged), Buffer.from(await concatPacks(packs)));
    });

    test('a delta whose base is in none of the packs is reported, not served', async () => {
        const thin = await pushPack(repo, `${B}\n^${A}\n`);
        const hasRef = parsePack(thin).some((e) => e.type === 7);
        assert.ok(hasRef, "the thin push really carries a REF_DELTA to a base outside it");
        const other = await pushPack(repo, `${D}\n^${C}\n`);
        await assert.rejects(() => mergePacks([other, thin]), /no base/);
    });
    test('a remembered index gives the same ids, and a new thin pack resolves against a remembered one', async () => {
        const packs = [
            await pushPack(repo, `${A}\n`),
            await pushPack(repo, `${B}\n^${A}\n`),
            await pushPack(repo, `${C}\n^${B}\n`),
            await pushPack(repo, `${D}\n^${C}\n`),
        ];
        assert.ok(parsePack(packs[1]).some((e) => e.type === 7), 'pack 1 is thin: a REF_DELTA into pack 0');
        const full = await indexPacks(packs);
        // Every split of known / not yet known gives the identical index.
        for (let k = 0; k <= packs.length; k++) {
            const known = full.slice(0, k).map((idx) => JSON.parse(JSON.stringify(idx)));
            assert.deepEqual(await indexPacks(packs, known), full, `first ${k} pack(s) known`);
        }
    });

    test('mergePacks remembers indexes, reuses them byte for byte, and ignores one that does not fit', async () => {
        const packs = [
            await pushPack(repo, `${A}\n`),
            await pushPack(repo, `${B}\n^${A}\n`),
            await pushPack(repo, `${C}\n^${B}\n`),
        ];
        const store = new Map();
        const gets = [], puts = [];
        const indexCache = {
            async get(id) { gets.push(id); return store.has(id) ? JSON.parse(store.get(id)) : null; },
            async put(id, index) { puts.push(id); store.set(id, JSON.stringify(index)); },
        };
        const packIds = ['p0', 'p1', 'p2'];
        const first = await mergePacks(packs, { packIds, indexCache });
        assert.deepEqual(puts, packIds);
        const again = await mergePacks(packs, { packIds, indexCache });
        assert.deepEqual(puts, packIds, 'nothing re-indexed');
        assert.deepEqual(Buffer.from(again), Buffer.from(first));
        assert.equal(again.dropped, first.dropped);
        assert.ok(first.dropped > 0);

        // A new push: only it is indexed.
        const p3 = await pushPack(repo, `${D}\n^${C}\n`);
        const grown = await mergePacks([...packs, p3], { packIds: [...packIds, 'p3'], indexCache });
        assert.deepEqual(puts, [...packIds, 'p3']);
        assert.deepEqual(Buffer.from(grown), Buffer.from(await mergePacks([...packs, p3])));

        // A cached index with the wrong record count is not trusted.
        store.set('p1', JSON.stringify([{ start: 12 }]));
        const healed = await mergePacks(packs, { packIds, indexCache });
        assert.deepEqual(Buffer.from(healed), Buffer.from(first));
        // A cache that throws is the same as no cache.
        const broken = { get: async () => { throw new Error('x'); }, put: async () => { throw new Error('y'); } };
        assert.deepEqual(Buffer.from(await mergePacks(packs, { packIds, indexCache: broken })), Buffer.from(first));
    });
});
