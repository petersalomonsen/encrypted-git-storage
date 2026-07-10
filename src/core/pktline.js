// git pkt-line framing (protocol v0), shared by the service worker's smart-HTTP
// implementation and its tests. Env-agnostic: Uint8Array in/out only.
//
// A pkt-line is a 4-hex-digit length (including the 4 bytes themselves) followed
// by the payload. "0000" is the flush-pkt (section separator, no payload).

const te = new TextEncoder();
const td = new TextDecoder();

export const FLUSH = new Uint8Array([0x30, 0x30, 0x30, 0x30]); // "0000"

export function concatBytes(...chunks) {
    const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
}

/** Frame one pkt-line. Accepts a string (utf-8 encoded) or raw bytes. */
export function pktLine(data) {
    const payload = typeof data === 'string' ? te.encode(data) : data;
    const len = payload.length + 4;
    if (len > 0xffff) throw new Error(`pkt-line too long: ${len}`);
    return concatBytes(te.encode(len.toString(16).padStart(4, '0')), payload);
}

/** Frame many pkt-lines and terminate with a flush-pkt. */
export function pktLines(lines) {
    return concatBytes(...lines.map(pktLine), FLUSH);
}

/**
 * Parse pkt-lines from `bytes` starting at `offset`, stopping at the first
 * flush-pkt (or end of input). Returns:
 *   { lines: string[],  // utf-8 payloads, trailing \n stripped
 *     next: number }    // offset just past the flush-pkt / end
 * Anything after `next` is raw payload (e.g. the packfile in a receive-pack
 * request body follows the command section's flush-pkt).
 */
export function parsePktSection(bytes, offset = 0) {
    const lines = [];
    while (offset < bytes.length) {
        const len = parseInt(td.decode(bytes.subarray(offset, offset + 4)), 16);
        if (Number.isNaN(len)) throw new Error(`bad pkt-line length at offset ${offset}`);
        if (len === 0) { offset += 4; break; } // flush-pkt
        const payload = bytes.subarray(offset + 4, offset + len);
        lines.push(td.decode(payload).replace(/\n$/, ''));
        offset += len;
    }
    return { lines, next: offset };
}
