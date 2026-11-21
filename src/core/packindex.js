// Read a git packfile far enough to know every object's id — what `git
// index-pack` does — in plain JS, so a service worker can do it.
//
// Why the store needs this: it serves all its packs merged into one, and that
// is a valid pack only while no object is in two of them. Pushes break that
// more often than it looks. libgit2 (and git) hide only what the remote TIP
// holds when they build a push, so a commit that brings a file or directory
// back to content an OLDER commit had re-sends those objects — no merge
// needed. libgit2 then refuses the merged pack ("duplicate object … found in
// pack"), so no browser can clone or fetch. See dedupePacks below.
//
// A pack object's id is SHA-1("<type> <size>\0" + content). Deltas must be
// applied to get the content, and finding where one object ends needs the
// zlib stream decoded (the pack records no lengths) — so this carries its own
// small inflater: DecompressionStream cannot say how much input it consumed.
//
// Env-agnostic: WebCrypto SHA-1 (browser/SW/Node).

const PACK_MAGIC = 0x5041434b; // "PACK"
const OBJ_COMMIT = 1, OBJ_TREE = 2, OBJ_BLOB = 3, OBJ_TAG = 4, OBJ_OFS_DELTA = 6, OBJ_REF_DELTA = 7;
const TYPE_NAMES = { [OBJ_COMMIT]: 'commit', [OBJ_TREE]: 'tree', [OBJ_BLOB]: 'blob', [OBJ_TAG]: 'tag' };

// ---------------------------------------------------------------------------
// inflate (RFC 1950 zlib wrapper around RFC 1951 deflate)

const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
const CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/**
 * Canonical Huffman code → lookup table indexed by the next `bits` input bits
 * (LSB first). Each entry is (symbol << 4) | codeLength; 0 = no such code.
 */
function buildTable(lengths) {
    let bits = 0;
    const counts = new Uint16Array(16);
    for (const l of lengths) { counts[l]++; if (l > bits) bits = l; }
    counts[0] = 0;
    const table = new Uint32Array(1 << Math.max(bits, 1));
    const next = new Uint16Array(16);
    for (let len = 1, code = 0; len < 16; len++) {
        code = (code + counts[len - 1]) << 1;
        next[len] = code;
    }
    for (let sym = 0; sym < lengths.length; sym++) {
        const len = lengths[sym];
        if (!len) continue;
        let code = next[len]++, rev = 0;
        for (let i = 0; i < len; i++) { rev = (rev << 1) | (code & 1); code >>= 1; }
        for (let i = rev; i < table.length; i += 1 << len) table[i] = (sym << 4) | len;
    }
    return { table, bits: Math.max(bits, 1) };
}

let FIXED = null;
function fixedTables() {
    if (!FIXED) {
        const lit = new Uint8Array(288);
        lit.fill(8, 0, 144); lit.fill(9, 144, 256); lit.fill(7, 256, 280); lit.fill(8, 280, 288);
        FIXED = { lit: buildTable(lit), dist: buildTable(new Uint8Array(30).fill(5)) };
    }
    return FIXED;
}

/**
 * Inflate the zlib stream at `src[start…]` into exactly `size` bytes.
 * @returns {{ data: Uint8Array, end: number }} end = offset just past the
 *   stream's adler32 trailer, i.e. where the next pack object starts.
 */
export function inflateAt(src, start, size) {
    const out = new Uint8Array(size);
    let op = 0;
    let pos = start + 2; // skip the zlib header (CMF, FLG)
    if ((src[start] & 0x0f) !== 8 || ((src[start] << 8) | src[start + 1]) % 31 !== 0) {
        throw new Error(`not a zlib stream at offset ${start}`);
    }
    if (src[start + 1] & 0x20) throw new Error(`zlib preset dictionary at offset ${start}`);
    let buf = 0, cnt = 0;
    // Bytes past the end of `src` read as 0; whatever was not consumed is
    // handed back before the trailer, so `end` is still exact.
    const need = (n) => { while (cnt < n) { buf |= (src[pos++] | 0) << cnt; cnt += 8; } };
    const take = (n) => { need(n); const v = buf & ((1 << n) - 1); buf >>>= n; cnt -= n; return v; };
    const decode = ({ table, bits }) => {
        need(bits);
        const e = table[buf & ((1 << bits) - 1)];
        const len = e & 15;
        if (!len) throw new Error(`invalid Huffman code in zlib stream at offset ${start}`);
        buf >>>= len; cnt -= len;
        return e >> 4;
    };

    for (let final = 0; !final;) {
        final = take(1);
        const type = take(2);
        if (type === 0) {
            // stored: drop to a byte boundary, hand back whole buffered bytes
            buf = 0; pos -= cnt >> 3; cnt = 0;
            const len = src[pos] | (src[pos + 1] << 8);
            const nlen = src[pos + 2] | (src[pos + 3] << 8);
            if ((len ^ 0xffff) !== nlen) throw new Error(`corrupt stored block at offset ${start}`);
            pos += 4;
            if (op + len > size || pos + len > src.length) throw new Error(`stored block overruns at offset ${start}`);
            out.set(src.subarray(pos, pos + len), op);
            op += len; pos += len;
            continue;
        }
        let lit, dist;
        if (type === 1) {
            ({ lit, dist } = fixedTables());
        } else if (type === 2) {
            const hlit = take(5) + 257, hdist = take(5) + 1, hclen = take(4) + 4;
            const cl = new Uint8Array(19);
            for (let i = 0; i < hclen; i++) cl[CLORDER[i]] = take(3);
            const clTable = buildTable(cl);
            const lengths = new Uint8Array(hlit + hdist);
            for (let i = 0; i < lengths.length;) {
                const sym = decode(clTable);
                if (sym < 16) { lengths[i++] = sym; continue; }
                let rep, val = 0;
                if (sym === 16) {
                    if (i === 0) throw new Error(`repeat with no previous length at offset ${start}`);
                    val = lengths[i - 1]; rep = 3 + take(2);
                } else if (sym === 17) rep = 3 + take(3);
                else rep = 11 + take(7);
                if (i + rep > lengths.length) throw new Error(`code lengths overrun at offset ${start}`);
                lengths.fill(val, i, i + rep); i += rep;
            }
            lit = buildTable(lengths.subarray(0, hlit));
            dist = buildTable(lengths.subarray(hlit));
        } else {
            throw new Error(`invalid deflate block type at offset ${start}`);
        }
        for (;;) {
            const sym = decode(lit);
            if (sym < 256) {
                if (op >= size) throw new Error(`inflated past the declared size at offset ${start}`);
                out[op++] = sym;
            } else if (sym === 256) {
                break;
            } else {
                const li = sym - 257;
                if (li >= 29) throw new Error(`invalid length symbol at offset ${start}`);
                const len = LBASE[li] + take(LEXT[li]);
                const di = decode(dist);
                if (di >= 30) throw new Error(`invalid distance symbol at offset ${start}`);
                const d = DBASE[di] + take(DEXT[di]);
                if (d > op) throw new Error(`distance too far back at offset ${start}`);
                if (op + len > size) throw new Error(`inflated past the declared size at offset ${start}`);
                for (let i = 0; i < len; i++, op++) out[op] = out[op - d];
            }
        }
    }
    if (op !== size) throw new Error(`object at offset ${start} inflated to ${op} bytes, header says ${size}`);
    pos -= cnt >> 3; // whole bytes still buffered were never part of the stream
    const end = pos + 4; // adler32
    if (end > src.length) throw new Error(`zlib stream at offset ${start} runs past the pack`);
    return { data: out, end };
}

// ---------------------------------------------------------------------------
// deltas

function readVarint(d, p) {
    let v = 0, shift = 0, c;
    do { c = d[p++]; v += (c & 0x7f) * 2 ** shift; shift += 7; } while (c & 0x80);
    return [v, p];
}

/** Apply a git delta to its base. */
export function applyDelta(base, delta) {
    let [srcSize, p] = readVarint(delta, 0);
    let dstSize;
    [dstSize, p] = readVarint(delta, p);
    if (srcSize !== base.length) throw new Error(`delta expects a ${srcSize}-byte base, got ${base.length}`);
    const out = new Uint8Array(dstSize);
    let op = 0;
    while (p < delta.length) {
        const cmd = delta[p++];
        if (cmd & 0x80) {
            let off = 0, len = 0;
            if (cmd & 0x01) off |= delta[p++];
            if (cmd & 0x02) off |= delta[p++] << 8;
            if (cmd & 0x04) off |= delta[p++] << 16;
            if (cmd & 0x08) off += delta[p++] * 2 ** 24;
            if (cmd & 0x10) len |= delta[p++];
            if (cmd & 0x20) len |= delta[p++] << 8;
            if (cmd & 0x40) len |= delta[p++] << 16;
            if (len === 0) len = 0x10000;
            if (off + len > base.length || op + len > dstSize) throw new Error('delta copy out of range');
            out.set(base.subarray(off, off + len), op);
            op += len;
        } else if (cmd) {
            if (op + cmd > dstSize || p + cmd > delta.length) throw new Error('delta insert out of range');
            out.set(delta.subarray(p, p + cmd), op);
            op += cmd; p += cmd;
        } else {
            throw new Error('delta opcode 0 is reserved');
        }
    }
    if (op !== dstSize) throw new Error(`delta produced ${op} bytes, expected ${dstSize}`);
    return out;
}

// ---------------------------------------------------------------------------
// pack parsing

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** A git object's id: SHA-1 of "<type> <size>\0" + content. */
async function objectId(type, content) {
    const head = new TextEncoder().encode(`${TYPE_NAMES[type]} ${content.length}\0`);
    const buf = new Uint8Array(head.length + content.length);
    buf.set(head, 0);
    buf.set(content, head.length);
    return hex(new Uint8Array(await crypto.subtle.digest('SHA-1', buf)));
}

/**
 * Walk one pack's object records.
 * @returns {Array<{start, dataStart, end, type, size, baseOffset?, baseOid?}>}
 */
export function parsePack(pack) {
    const entries = [];
    for (const [entry] of records(pack)) entries.push(entry);
    return entries;
}

/**
 * The records of a pack with their inflated bytes, one at a time. The pack
 * records no lengths, so every object is inflated to find the next.
 * @returns {Generator<[entry, Uint8Array]>}
 */
function* records(pack) {
    if (pack.length < 32) throw new Error('pack too small');
    const dv = new DataView(pack.buffer, pack.byteOffset, pack.byteLength);
    if (dv.getUint32(0) !== PACK_MAGIC) throw new Error('bad pack magic');
    if (dv.getUint32(4) !== 2) throw new Error(`unsupported pack version ${dv.getUint32(4)}`);
    const count = dv.getUint32(8);
    const limit = pack.length - 20;
    let p = 12;
    for (let i = 0; i < count; i++) {
        const start = p;
        let c = pack[p++];
        const type = (c >> 4) & 7;
        let size = c & 15, shift = 4;
        while (c & 0x80) { c = pack[p++]; size += (c & 0x7f) * 2 ** shift; shift += 7; }
        const entry = { start, type, size };
        if (type === OBJ_OFS_DELTA) {
            c = pack[p++];
            let off = c & 0x7f;
            while (c & 0x80) { c = pack[p++]; off = (off + 1) * 128 + (c & 0x7f); }
            entry.baseOffset = start - off;
            if (entry.baseOffset < 12) throw new Error(`OFS_DELTA at ${start} points before the pack`);
        } else if (type === OBJ_REF_DELTA) {
            entry.baseOid = hex(pack.subarray(p, p + 20));
            p += 20;
        } else if (!TYPE_NAMES[type]) {
            throw new Error(`unknown object type ${type} at offset ${start}`);
        }
        entry.dataStart = p;
        const { data, end } = inflateAt(pack, p, size);
        p = end;
        if (p > limit) throw new Error(`object at ${start} runs into the pack trailer`);
        entry.end = p;
        yield [entry, data];
    }
    if (p !== limit) throw new Error(`pack has ${limit - p} stray bytes before its trailer`);
}

/** The fields of an indexed record — all a later merge needs, JSON-safe. */
const RECORD_FIELDS = ['start', 'dataStart', 'end', 'type', 'size', 'baseOffset', 'baseOid', 'oid', 'objType'];
const plainRecord = (e) => Object.fromEntries(RECORD_FIELDS.filter((f) => e[f] !== undefined).map((f) => [f, e[f]]));

/**
 * Object ids of every record in a set of packs (in order). REF_DELTA bases may
 * be in any of the packs — that is how thin pushes are stored.
 *
 * Resolving every delta is most of the cost (each version of each file is
 * rebuilt to be hashed), and a pack's index never changes, so a caller can
 * pass what it learnt before: `known[i]`, if given, is pack i's index from an
 * earlier call and that pack is not read again — except for the few objects a
 * new pack's deltas are based on.
 *
 * @param {Uint8Array[]} packs
 * @param {Array<Array<object>|null|undefined>} [known]
 * @returns {Promise<Array<Array<{start, dataStart, end, type, size, baseOffset?, baseOid?, oid, objType}>>>}
 *   one array per pack, plain data (safe to JSON and pass back as `known`).
 */
export async function indexPacks(packs, known = []) {
    // One pass inflates every pack not known yet: a full object's id is
    // computed right there, and a delta's (small) instructions are kept.
    // Digests run concurrently, a bounded number of bytes at a time.
    const all = [];
    let batch = [], batchBytes = 0;
    const flush = async () => { await Promise.all(batch); batch = []; batchBytes = 0; };
    for (let pi = 0; pi < packs.length; pi++) {
        if (known[pi]) {
            all.push(known[pi].map((e) => ({ ...e, pi })));
            continue;
        }
        const entries = [];
        for (const [e, data] of records(packs[pi])) {
            e.pi = pi;
            entries.push(e);
            if (e.type === OBJ_OFS_DELTA || e.type === OBJ_REF_DELTA) {
                e.delta = data;
                continue;
            }
            e.objType = e.type;
            batch.push(objectId(e.type, data).then((oid) => { e.oid = oid; }));
            batchBytes += data.length;
            if (batchBytes > 32 * 1024 * 1024 || batch.length >= 256) await flush();
        }
        all.push(entries);
    }
    await flush();

    const byOffset = all.map((entries) => new Map(entries.map((e) => [e.start, e])));
    const byOid = new Map();
    const ofsChildren = new Map(); // entry -> [unresolved delta entries based on it]
    const refChildren = new Map(); // base oid -> [unresolved delta entries]
    for (const entries of all) {
        for (const e of entries) {
            if (e.oid) { if (!byOid.has(e.oid)) byOid.set(e.oid, e); continue; }
            if (e.type === OBJ_OFS_DELTA) {
                const base = byOffset[e.pi].get(e.baseOffset);
                if (!base) throw new Error(`OFS_DELTA at ${e.start} has no object at its base offset ${e.baseOffset}`);
                if (!ofsChildren.has(base)) ofsChildren.set(base, []);
                ofsChildren.get(base).push(e);
            } else {
                if (!refChildren.has(e.baseOid)) refChildren.set(e.baseOid, []);
                refChildren.get(e.baseOid).push(e);
            }
        }
    }

    // The content of an already-indexed object: inflate it, applying its
    // delta chain if it is one (the base of a new pack's delta can be).
    const contentOf = (e) => {
        const data = inflateAt(packs[e.pi], e.dataStart, e.size).data;
        if (e.type === OBJ_OFS_DELTA) return applyDelta(contentOf(byOffset[e.pi].get(e.baseOffset)), data);
        if (e.type === OBJ_REF_DELTA) return applyDelta(contentOf(byOid.get(e.baseOid)), data);
        return data;
    };

    // Resolve deltas depth-first from each object that has unresolved ones,
    // so a base's content is held only while its own chain is being resolved.
    // Each pending delta is handed out once: an object resolved inside a
    // chain is met again by the outer loop, and must not rebuild that chain.
    const children = (e) => {
        const kids = [...(ofsChildren.get(e) ?? []), ...(refChildren.get(e.oid) ?? [])];
        ofsChildren.delete(e);
        refChildren.delete(e.oid); // only one copy of an oid feeds its REF children
        return kids.filter((k) => !k.oid);
    };
    for (const root of all.flat()) {
        if (!root.oid) continue;
        const kids = children(root);
        if (kids.length === 0) continue;
        const base = contentOf(root);
        const stack = kids.map((k) => [k, base, root.objType]);
        while (stack.length > 0) {
            const [e, baseData, baseType] = stack.pop();
            if (e.oid) continue;
            const data = applyDelta(baseData, e.delta);
            e.objType = baseType;
            e.oid = await objectId(baseType, data);
            if (!byOid.has(e.oid)) byOid.set(e.oid, e);
            for (const k of children(e)) stack.push([k, data, baseType]);
        }
    }
    const unresolved = all.flat().filter((e) => !e.oid);
    if (unresolved.length > 0) {
        const e = unresolved[0];
        throw new Error(`${unresolved.length} delta(s) have no base in these packs (first: pack ${e.pi} offset ${e.start}${e.baseOid ? `, base ${e.baseOid}` : ''})`);
    }
    return all.map((entries) => entries.map(plainRecord));
}

// ---------------------------------------------------------------------------
// merging without duplicates

function entryHeader(type, size) {
    const bytes = [];
    let c = (type << 4) | (size & 15);
    let rest = Math.floor(size / 16);
    while (rest > 0) {
        bytes.push(c | 0x80);
        c = rest & 0x7f;
        rest = Math.floor(rest / 128);
    }
    bytes.push(c);
    return bytes;
}
const unhex = (s) => Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));

/**
 * The record bodies of packs merged into one, every object exactly once.
 * `known` is passed to indexPacks; the result carries `indexed` to remember.
 *
 * A later copy of an object is dropped. A pack that loses a record cannot keep
 * its OFS_DELTA records as they are — their distances may now span a gap, or
 * point at the dropped copy — so in such a pack every OFS_DELTA is rewritten
 * as a REF_DELTA naming its base by id (the delta data itself is unchanged:
 * the base's content is the same whichever copy holds it). Packs that lose
 * nothing are passed through byte for byte.
 *
 * @returns {Promise<{ bodies: Uint8Array[], count: number, dropped: number, indexed: object[][] }>}
 */
export async function dedupeRecords(packs, known = []) {
    const indexed = await indexPacks(packs, known);
    const seen = new Set();
    const bodies = [];
    let count = 0, dropped = 0;
    for (let pi = 0; pi < packs.length; pi++) {
        const pack = packs[pi];
        const entries = indexed[pi];
        const keep = entries.filter((e) => !seen.has(e.oid) && (seen.add(e.oid), true));
        count += keep.length;
        if (keep.length === entries.length) {
            bodies.push(pack.subarray(12, pack.length - 20));
            continue;
        }
        dropped += entries.length - keep.length;
        const oidAt = new Map(entries.map((e) => [e.start, e.oid]));
        const parts = [];
        for (const e of keep) {
            if (e.type === OBJ_OFS_DELTA) {
                parts.push(Uint8Array.from(entryHeader(OBJ_REF_DELTA, e.size)), unhex(oidAt.get(e.baseOffset)));
                parts.push(pack.subarray(e.dataStart, e.end));
            } else {
                parts.push(pack.subarray(e.start, e.end));
            }
        }
        const body = new Uint8Array(parts.reduce((n, b) => n + b.length, 0));
        let off = 0;
        for (const b of parts) { body.set(b, off); off += b.length; }
        bodies.push(body);
    }
    return { bodies, count, dropped, indexed };
}
