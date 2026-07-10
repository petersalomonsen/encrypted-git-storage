// Merge the store's append-only packfiles into ONE valid packfile — what a git
// smart-HTTP server must send in its upload-pack response.
//
// A packfile is:  12-byte header ("PACK", version, object count, all big-endian)
//                 + object records + 20-byte SHA-1 trailer of everything before it.
//
// Concatenating works because each source pack's object section is kept intact
// and contiguous:
//  - OFS_DELTA offsets are relative distances *within* a section → unchanged.
//  - REF_DELTA (thin-pack) bases live in *earlier* packs → present in the merged
//    stream, and `git index-pack` resolves REF_DELTA in-pack in any order.
// So merging packs in push order yields a self-contained, non-thin pack.
//
// Env-agnostic: WebCrypto SHA-1 (browser/SW/Node).

const PACK_MAGIC = 0x5041434b; // "PACK"

function header(view) {
    if (view.byteLength < 32) throw new Error('pack too small');
    const dv = new DataView(view.buffer, view.byteOffset, view.byteLength);
    if (dv.getUint32(0) !== PACK_MAGIC) throw new Error('bad pack magic');
    const version = dv.getUint32(4);
    if (version !== 2) throw new Error(`unsupported pack version ${version}`);
    return { count: dv.getUint32(8) };
}

/** Object count from a pack's header. */
export function packObjectCount(pack) {
    return header(pack).count;
}

/** Merge plaintext packs (in push order) into one valid pack. */
export async function concatPacks(packs) {
    let total = 0;
    const bodies = [];
    for (const pack of packs) {
        const { count } = header(pack);
        total += count;
        bodies.push(pack.subarray(12, pack.length - 20)); // strip header + SHA-1 trailer
    }

    const head = new Uint8Array(12);
    const dv = new DataView(head.buffer);
    dv.setUint32(0, PACK_MAGIC);
    dv.setUint32(4, 2);
    dv.setUint32(8, total);

    const bodyLen = bodies.reduce((n, b) => n + b.length, 0);
    const out = new Uint8Array(12 + bodyLen + 20);
    out.set(head, 0);
    let off = 12;
    for (const b of bodies) { out.set(b, off); off += b.length; }

    const sha = await crypto.subtle.digest('SHA-1', out.subarray(0, off));
    out.set(new Uint8Array(sha), off);
    return out;
}
