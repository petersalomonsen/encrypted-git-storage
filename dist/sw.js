// src/core/crypto.js
var MAGIC = new Uint8Array([69, 71, 83, 49]);
var IV_LEN = 12;
async function importKey(keyBytes) {
  if (keyBytes?.byteLength !== 32) {
    throw new Error(`key must be 32 bytes, got ${keyBytes?.byteLength}`);
  }
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}
async function encrypt(keyBytes, plaintext) {
  const key = await importKey(keyBytes);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const out = new Uint8Array(MAGIC.length + IV_LEN + ct.length);
  out.set(MAGIC, 0);
  out.set(iv, MAGIC.length);
  out.set(ct, MAGIC.length + IV_LEN);
  return out;
}
async function decrypt(keyBytes, framed) {
  const buf = new Uint8Array(framed);
  for (let i = 0; i < MAGIC.length; i++) {
    if (buf[i] !== MAGIC[i]) throw new Error("bad magic \u2014 not an EGS1 blob");
  }
  const iv = buf.subarray(MAGIC.length, MAGIC.length + IV_LEN);
  const ct = buf.subarray(MAGIC.length + IV_LEN);
  const key = await importKey(keyBytes);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct));
}
async function sha256hex(bytes) {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// src/core/format.js
var MANIFEST_VERSION = 1;
function emptyManifest() {
  return { version: MANIFEST_VERSION, refs: {}, packs: [], generation: 0 };
}
function serializeManifest(manifest) {
  return new TextEncoder().encode(JSON.stringify(manifest));
}
function parseManifest(bytes) {
  const manifest = JSON.parse(new TextDecoder().decode(bytes));
  if (manifest.version !== MANIFEST_VERSION) {
    throw new Error(`unsupported manifest version ${manifest.version} (expected ${MANIFEST_VERSION})`);
  }
  return manifest;
}
function nextPackIndex(manifest) {
  return manifest.packs.reduce((max, p) => Math.max(max, p.n + 1), 0);
}
function advanceManifest(manifest, { refUpdates = {}, pack = null } = {}) {
  const refs = { ...manifest.refs };
  for (const [name, sha] of Object.entries(refUpdates)) {
    if (sha === null) delete refs[name];
    else refs[name] = sha;
  }
  const packs = pack ? [...manifest.packs, pack] : [...manifest.packs];
  return { version: MANIFEST_VERSION, refs, packs, generation: manifest.generation + 1 };
}
function packsInOrder(manifest) {
  return [...manifest.packs].sort((a, b) => a.n - b.n);
}

// src/core/manifest-io.js
async function loadManifest(store, key) {
  const got = await store.getRefs();
  if (!got) return { manifest: emptyManifest(), etag: null };
  return { manifest: parseManifest(await decrypt(key, got.bytes)), etag: got.etag };
}
function encryptManifest(key, manifest) {
  return encrypt(key, serializeManifest(manifest));
}

// src/core/pktline.js
var te = new TextEncoder();
var td = new TextDecoder();
var FLUSH = new Uint8Array([48, 48, 48, 48]);
function concatBytes(...chunks) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}
function pktLine(data) {
  const payload = typeof data === "string" ? te.encode(data) : data;
  const len = payload.length + 4;
  if (len > 65535) throw new Error(`pkt-line too long: ${len}`);
  return concatBytes(te.encode(len.toString(16).padStart(4, "0")), payload);
}
function pktLines(lines) {
  return concatBytes(...lines.map(pktLine), FLUSH);
}
function parsePktSection(bytes, offset = 0) {
  const lines = [];
  while (offset < bytes.length) {
    const len = parseInt(td.decode(bytes.subarray(offset, offset + 4)), 16);
    if (Number.isNaN(len)) throw new Error(`bad pkt-line length at offset ${offset}`);
    if (len === 0) {
      offset += 4;
      break;
    }
    const payload = bytes.subarray(offset + 4, offset + len);
    lines.push(td.decode(payload).replace(/\n$/, ""));
    offset += len;
  }
  return { lines, next: offset };
}

// src/core/packindex.js
var PACK_MAGIC = 1346454347;
var OBJ_COMMIT = 1;
var OBJ_TREE = 2;
var OBJ_BLOB = 3;
var OBJ_TAG = 4;
var OBJ_OFS_DELTA = 6;
var OBJ_REF_DELTA = 7;
var TYPE_NAMES = { [OBJ_COMMIT]: "commit", [OBJ_TREE]: "tree", [OBJ_BLOB]: "blob", [OBJ_TAG]: "tag" };
var LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
var LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
var DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
var DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
var CLORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
function buildTable(lengths) {
  let bits = 0;
  const counts = new Uint16Array(16);
  for (const l of lengths) {
    counts[l]++;
    if (l > bits) bits = l;
  }
  counts[0] = 0;
  const table = new Uint32Array(1 << Math.max(bits, 1));
  const next = new Uint16Array(16);
  for (let len = 1, code = 0; len < 16; len++) {
    code = code + counts[len - 1] << 1;
    next[len] = code;
  }
  for (let sym = 0; sym < lengths.length; sym++) {
    const len = lengths[sym];
    if (!len) continue;
    let code = next[len]++, rev = 0;
    for (let i = 0; i < len; i++) {
      rev = rev << 1 | code & 1;
      code >>= 1;
    }
    for (let i = rev; i < table.length; i += 1 << len) table[i] = sym << 4 | len;
  }
  return { table, bits: Math.max(bits, 1) };
}
var FIXED = null;
function fixedTables() {
  if (!FIXED) {
    const lit = new Uint8Array(288);
    lit.fill(8, 0, 144);
    lit.fill(9, 144, 256);
    lit.fill(7, 256, 280);
    lit.fill(8, 280, 288);
    FIXED = { lit: buildTable(lit), dist: buildTable(new Uint8Array(30).fill(5)) };
  }
  return FIXED;
}
function inflateAt(src, start, size) {
  const out = new Uint8Array(size);
  let op = 0;
  let pos = start + 2;
  if ((src[start] & 15) !== 8 || (src[start] << 8 | src[start + 1]) % 31 !== 0) {
    throw new Error(`not a zlib stream at offset ${start}`);
  }
  if (src[start + 1] & 32) throw new Error(`zlib preset dictionary at offset ${start}`);
  let buf = 0, cnt = 0;
  const need = (n) => {
    while (cnt < n) {
      buf |= (src[pos++] | 0) << cnt;
      cnt += 8;
    }
  };
  const take = (n) => {
    need(n);
    const v = buf & (1 << n) - 1;
    buf >>>= n;
    cnt -= n;
    return v;
  };
  const decode = ({ table, bits }) => {
    need(bits);
    const e = table[buf & (1 << bits) - 1];
    const len = e & 15;
    if (!len) throw new Error(`invalid Huffman code in zlib stream at offset ${start}`);
    buf >>>= len;
    cnt -= len;
    return e >> 4;
  };
  for (let final = 0; !final; ) {
    final = take(1);
    const type = take(2);
    if (type === 0) {
      buf = 0;
      pos -= cnt >> 3;
      cnt = 0;
      const len = src[pos] | src[pos + 1] << 8;
      const nlen = src[pos + 2] | src[pos + 3] << 8;
      if ((len ^ 65535) !== nlen) throw new Error(`corrupt stored block at offset ${start}`);
      pos += 4;
      if (op + len > size || pos + len > src.length) throw new Error(`stored block overruns at offset ${start}`);
      out.set(src.subarray(pos, pos + len), op);
      op += len;
      pos += len;
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
      for (let i = 0; i < lengths.length; ) {
        const sym = decode(clTable);
        if (sym < 16) {
          lengths[i++] = sym;
          continue;
        }
        let rep, val = 0;
        if (sym === 16) {
          if (i === 0) throw new Error(`repeat with no previous length at offset ${start}`);
          val = lengths[i - 1];
          rep = 3 + take(2);
        } else if (sym === 17) rep = 3 + take(3);
        else rep = 11 + take(7);
        if (i + rep > lengths.length) throw new Error(`code lengths overrun at offset ${start}`);
        lengths.fill(val, i, i + rep);
        i += rep;
      }
      lit = buildTable(lengths.subarray(0, hlit));
      dist = buildTable(lengths.subarray(hlit));
    } else {
      throw new Error(`invalid deflate block type at offset ${start}`);
    }
    for (; ; ) {
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
  pos -= cnt >> 3;
  const end = pos + 4;
  if (end > src.length) throw new Error(`zlib stream at offset ${start} runs past the pack`);
  return { data: out, end };
}
function readVarint(d, p) {
  let v = 0, shift = 0, c;
  do {
    c = d[p++];
    v += (c & 127) * 2 ** shift;
    shift += 7;
  } while (c & 128);
  return [v, p];
}
function applyDelta(base, delta) {
  let [srcSize, p] = readVarint(delta, 0);
  let dstSize;
  [dstSize, p] = readVarint(delta, p);
  if (srcSize !== base.length) throw new Error(`delta expects a ${srcSize}-byte base, got ${base.length}`);
  const out = new Uint8Array(dstSize);
  let op = 0;
  while (p < delta.length) {
    const cmd = delta[p++];
    if (cmd & 128) {
      let off = 0, len = 0;
      if (cmd & 1) off |= delta[p++];
      if (cmd & 2) off |= delta[p++] << 8;
      if (cmd & 4) off |= delta[p++] << 16;
      if (cmd & 8) off += delta[p++] * 2 ** 24;
      if (cmd & 16) len |= delta[p++];
      if (cmd & 32) len |= delta[p++] << 8;
      if (cmd & 64) len |= delta[p++] << 16;
      if (len === 0) len = 65536;
      if (off + len > base.length || op + len > dstSize) throw new Error("delta copy out of range");
      out.set(base.subarray(off, off + len), op);
      op += len;
    } else if (cmd) {
      if (op + cmd > dstSize || p + cmd > delta.length) throw new Error("delta insert out of range");
      out.set(delta.subarray(p, p + cmd), op);
      op += cmd;
      p += cmd;
    } else {
      throw new Error("delta opcode 0 is reserved");
    }
  }
  if (op !== dstSize) throw new Error(`delta produced ${op} bytes, expected ${dstSize}`);
  return out;
}
var hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
async function objectId(type, content) {
  const head = new TextEncoder().encode(`${TYPE_NAMES[type]} ${content.length}\0`);
  const buf = new Uint8Array(head.length + content.length);
  buf.set(head, 0);
  buf.set(content, head.length);
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-1", buf)));
}
function* records(pack) {
  if (pack.length < 32) throw new Error("pack too small");
  const dv = new DataView(pack.buffer, pack.byteOffset, pack.byteLength);
  if (dv.getUint32(0) !== PACK_MAGIC) throw new Error("bad pack magic");
  if (dv.getUint32(4) !== 2) throw new Error(`unsupported pack version ${dv.getUint32(4)}`);
  const count = dv.getUint32(8);
  const limit = pack.length - 20;
  let p = 12;
  for (let i = 0; i < count; i++) {
    const start = p;
    let c = pack[p++];
    const type = c >> 4 & 7;
    let size = c & 15, shift = 4;
    while (c & 128) {
      c = pack[p++];
      size += (c & 127) * 2 ** shift;
      shift += 7;
    }
    const entry = { start, type, size };
    if (type === OBJ_OFS_DELTA) {
      c = pack[p++];
      let off = c & 127;
      while (c & 128) {
        c = pack[p++];
        off = (off + 1) * 128 + (c & 127);
      }
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
var RECORD_FIELDS = ["start", "dataStart", "end", "type", "size", "baseOffset", "baseOid", "oid", "objType"];
var plainRecord = (e) => Object.fromEntries(RECORD_FIELDS.filter((f) => e[f] !== void 0).map((f) => [f, e[f]]));
async function indexPacks(packs, known = []) {
  const all = [];
  let batch = [], batchBytes = 0;
  const flush = async () => {
    await Promise.all(batch);
    batch = [];
    batchBytes = 0;
  };
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
      batch.push(objectId(e.type, data).then((oid) => {
        e.oid = oid;
      }));
      batchBytes += data.length;
      if (batchBytes > 32 * 1024 * 1024 || batch.length >= 256) await flush();
    }
    all.push(entries);
  }
  await flush();
  const byOffset = all.map((entries) => new Map(entries.map((e) => [e.start, e])));
  const byOid = /* @__PURE__ */ new Map();
  const ofsChildren = /* @__PURE__ */ new Map();
  const refChildren = /* @__PURE__ */ new Map();
  for (const entries of all) {
    for (const e of entries) {
      if (e.oid) {
        if (!byOid.has(e.oid)) byOid.set(e.oid, e);
        continue;
      }
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
  const contentOf = (e) => {
    const data = inflateAt(packs[e.pi], e.dataStart, e.size).data;
    if (e.type === OBJ_OFS_DELTA) return applyDelta(contentOf(byOffset[e.pi].get(e.baseOffset)), data);
    if (e.type === OBJ_REF_DELTA) return applyDelta(contentOf(byOid.get(e.baseOid)), data);
    return data;
  };
  const children = (e) => {
    const kids = [...ofsChildren.get(e) ?? [], ...refChildren.get(e.oid) ?? []];
    ofsChildren.delete(e);
    refChildren.delete(e.oid);
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
    throw new Error(`${unresolved.length} delta(s) have no base in these packs (first: pack ${e.pi} offset ${e.start}${e.baseOid ? `, base ${e.baseOid}` : ""})`);
  }
  return all.map((entries) => entries.map(plainRecord));
}
function entryHeader(type, size) {
  const bytes = [];
  let c = type << 4 | size & 15;
  let rest = Math.floor(size / 16);
  while (rest > 0) {
    bytes.push(c | 128);
    c = rest & 127;
    rest = Math.floor(rest / 128);
  }
  bytes.push(c);
  return bytes;
}
var unhex = (s) => Uint8Array.from(s.match(/../g), (h) => parseInt(h, 16));
async function dedupeRecords(packs, known = []) {
  const indexed = await indexPacks(packs, known);
  const seen = /* @__PURE__ */ new Set();
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
    for (const b of parts) {
      body.set(b, off);
      off += b.length;
    }
    bodies.push(body);
  }
  return { bodies, count, dropped, indexed };
}

// src/core/packcat.js
var PACK_MAGIC2 = 1346454347;
function header(view) {
  if (view.byteLength < 32) throw new Error("pack too small");
  const dv = new DataView(view.buffer, view.byteOffset, view.byteLength);
  if (dv.getUint32(0) !== PACK_MAGIC2) throw new Error("bad pack magic");
  const version = dv.getUint32(4);
  if (version !== 2) throw new Error(`unsupported pack version ${version}`);
  return { count: dv.getUint32(8) };
}
function packObjectCount(pack) {
  return header(pack).count;
}
async function concatPacks(packs) {
  let total = 0;
  const bodies = [];
  for (const pack of packs) {
    const { count } = header(pack);
    total += count;
    bodies.push(pack.subarray(12, pack.length - 20));
  }
  return assemble(bodies, total);
}
async function mergePacks(packs, { packIds = null, indexCache = null } = {}) {
  if (packs.length <= 1) {
    const merged2 = await concatPacks(packs);
    merged2.dropped = 0;
    return merged2;
  }
  const useCache = indexCache && packIds?.length === packs.length && packIds.every(Boolean);
  const known = useCache ? await Promise.all(packIds.map(async (id, i) => {
    const index = await indexCache.get(id).catch(() => null);
    return Array.isArray(index) && index.length === packObjectCount(packs[i]) ? index : null;
  })) : [];
  const { bodies, count, dropped, indexed } = await dedupeRecords(packs, known);
  if (useCache) {
    for (let i = 0; i < packs.length; i++) {
      if (!known[i]) await indexCache.put(packIds[i], indexed[i]).catch(() => {
      });
    }
  }
  const merged = await assemble(bodies, count);
  merged.dropped = dropped;
  return merged;
}
async function assemble(bodies, total) {
  const head = new Uint8Array(12);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, PACK_MAGIC2);
  dv.setUint32(4, 2);
  dv.setUint32(8, total);
  const bodyLen = bodies.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(12 + bodyLen + 20);
  out.set(head, 0);
  let off = 12;
  for (const b of bodies) {
    out.set(b, off);
    off += b.length;
  }
  const sha = await crypto.subtle.digest("SHA-1", out.subarray(0, off));
  out.set(new Uint8Array(sha), off);
  return out;
}

// src/core/smart-http.js
var ZERO_SHA = "0".repeat(40);
var CAPS = {
  "git-upload-pack": "agent=egit/1",
  "git-receive-pack": "report-status delete-refs agent=egit/1"
};
function advertisement(manifest, service) {
  let caps = CAPS[service];
  const entries = Object.entries(manifest.refs).sort(([a], [b]) => a < b ? -1 : 1);
  const lines = [];
  if (entries.length === 0) {
    lines.push(`${ZERO_SHA} capabilities^{}\0${caps}
`);
    return lines;
  }
  if (service === "git-upload-pack") {
    const head = manifest.refs["refs/heads/main"] ? "refs/heads/main" : Object.keys(manifest.refs).find((r) => r.startsWith("refs/heads/"));
    if (head) {
      lines.push(`${manifest.refs[head]} HEAD\0${caps} symref=HEAD:${head}
`);
      caps = null;
    }
  }
  for (const [name, sha] of entries) {
    lines.push(caps ? `${sha} ${name}\0${caps}
` : `${sha} ${name}
`);
    caps = null;
  }
  return lines;
}
async function handleInfoRefs(service, store, key, { repack = false } = {}) {
  if (!CAPS[service]) throw new Error(`unsupported service: ${service}`);
  if (repack && service !== "git-receive-pack") {
    throw new Error(`repack is a push: ${service} is not available on it`);
  }
  const { manifest } = await loadManifest(store, key);
  const advertised = repack ? { ...manifest, refs: {} } : manifest;
  const body = concatBytes(
    pktLine(`# service=${service}
`),
    FLUSH,
    pktLines(advertisement(advertised, service))
  );
  return { body, contentType: `application/x-${service}-advertisement` };
}
async function handleUploadPack(reqBody, store, key, { indexCache = null } = {}) {
  const lines = [];
  for (let off = 0; off < reqBody.length; ) {
    const section = parsePktSection(reqBody, off);
    lines.push(...section.lines);
    off = section.next;
  }
  const done = lines.some((l) => l === "done");
  if (!done) {
    return { body: pktLine("NAK\n"), contentType: "application/x-git-upload-pack-result" };
  }
  const { manifest } = await loadManifest(store, key);
  const packs = [];
  const packIds = [];
  for (const p of packsInOrder(manifest)) {
    const pack = await decrypt(key, await store.getPack(p.n));
    if (packObjectCount(pack) > 0) {
      packs.push(pack);
      packIds.push(p.sha);
    }
  }
  const merged = await mergePacks(packs, { packIds, indexCache });
  return {
    body: concatBytes(pktLine("NAK\n"), merged),
    contentType: "application/x-git-upload-pack-result"
  };
}
async function handleReceivePack(reqBody, store, key, { repack = false } = {}) {
  const { lines, next } = parsePktSection(reqBody);
  const packBytes = reqBody.subarray(next);
  const commands = lines.map((l) => {
    const [oldSha, newSha, ref] = l.split("\0")[0].split(" ");
    return { oldSha, newSha, ref };
  }).filter((c) => c.ref);
  if (commands.length === 0) {
    if (packBytes.length === 0) {
      return { body: new Uint8Array(0), contentType: "application/x-git-receive-pack-result" };
    }
    throw new Error("receive-pack: no commands");
  }
  const report = (refLines) => ({
    body: pktLines(["unpack ok\n", ...refLines]),
    contentType: "application/x-git-receive-pack-result"
  });
  const hasPack = packBytes.length >= 32 && packObjectCount(packBytes) > 0;
  const packMeta = hasPack ? { sha: await sha256hex(packBytes), size: packBytes.length } : null;
  const encryptedPack = hasPack ? await encrypt(key, packBytes) : null;
  let storedAt = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    const { manifest, etag } = await loadManifest(store, key);
    if (repack) {
      const wrong = commands.filter((c) => c.newSha !== manifest.refs[c.ref]);
      const missing = Object.keys(manifest.refs).filter((ref) => !commands.some((c) => c.ref === ref));
      if (wrong.length > 0 || missing.length > 0) {
        return report([
          ...commands.map((c) => wrong.includes(c) ? `ng ${c.ref} repack must offer the store's current tip \u2014 fetch first
` : `ng ${c.ref} not attempted
`),
          ...missing.map((ref) => `ng ${ref} repack must cover every ref
`)
        ]);
      }
      if (!packMeta) {
        return report(commands.map((c) => `ng ${c.ref} repack carried no packfile
`));
      }
      if (storedAt === null) {
        storedAt = nextPackIndex(manifest);
        while (!await store.putPack(storedAt, encryptedPack)) storedAt++;
      }
      const repacked = {
        version: MANIFEST_VERSION,
        refs: manifest.refs,
        packs: [{ n: storedAt, ...packMeta }],
        generation: manifest.generation + 1
      };
      if (await store.putRefs(await encryptManifest(key, repacked), etag)) {
        return report(commands.map((c) => `ok ${c.ref}
`));
      }
      continue;
    }
    const stale = commands.filter((c) => (manifest.refs[c.ref] ?? ZERO_SHA) !== c.oldSha);
    if (stale.length > 0) {
      return report(commands.map((c) => stale.includes(c) ? `ng ${c.ref} fetch first
` : `ng ${c.ref} not attempted
`));
    }
    if (packBytes.length === 0) {
      const known = new Set(Object.values(manifest.refs));
      const missing = commands.filter((c) => c.newSha !== ZERO_SHA && !known.has(c.newSha));
      if (missing.length > 0) {
        return report(commands.map((c) => missing.includes(c) ? `ng ${c.ref} push carried no packfile for new objects
` : `ng ${c.ref} not attempted
`));
      }
    }
    let pack = null;
    if (packMeta) {
      if (storedAt === null) {
        storedAt = nextPackIndex(manifest);
        while (!await store.putPack(storedAt, encryptedPack)) storedAt++;
      }
      pack = { n: storedAt, ...packMeta };
    }
    const refUpdates = Object.fromEntries(commands.map((c) => [c.ref, c.newSha === ZERO_SHA ? null : c.newSha]));
    const nextManifest = advanceManifest(manifest, { refUpdates, pack });
    if (await store.putRefs(await encryptManifest(key, nextManifest), etag)) {
      return report(commands.map((c) => `ok ${c.ref}
`));
    }
  }
  return report(commands.map((c) => `ng ${c.ref} refs CAS kept failing \u2014 try again
`));
}

// src/core/store-client.js
function makeStoreClient(base, repoId, extraHeaders = {}) {
  const headers = { "x-repo-id": repoId, "content-type": "application/octet-stream", ...extraHeaders };
  return {
    // -> { bytes, etag } | null when absent
    async getRefs() {
      const res = await fetch(`${base}/refs`, { headers });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`GET refs failed: ${res.status}`);
      return { bytes: new Uint8Array(await res.arrayBuffer()), etag: res.headers.get("etag") };
    },
    // CAS write: etag=null means create-if-absent. -> true | false on 412 conflict
    async putRefs(bytes, etag) {
      const res = await fetch(`${base}/refs`, {
        method: "PUT",
        body: bytes,
        headers: { ...headers, ...etag ? { "if-match": etag } : { "if-none-match": "*" } }
      });
      if (res.status === 412) return false;
      if (!res.ok) throw new Error(`PUT refs failed: ${res.status}`);
      return true;
    },
    async getPack(n) {
      const res = await fetch(`${base}/packs/${n}`, { headers });
      if (!res.ok) throw new Error(`GET pack ${n} failed: ${res.status}`);
      return new Uint8Array(await res.arrayBuffer());
    },
    // create-only (packs are immutable). -> true | false when the index is taken
    async putPack(n, bytes) {
      const res = await fetch(`${base}/packs/${n}`, { method: "PUT", body: bytes, headers });
      if (res.status === 412) return false;
      if (!res.ok) throw new Error(`PUT pack ${n} failed: ${res.status}`);
      return true;
    },
    // every stored pack (whether the manifest references it or not)
    // -> [{ n, size, lastModified (epoch ms) }]
    async listPacks() {
      const res = await fetch(`${base}/packs`, { headers });
      if (!res.ok) throw new Error(`GET packs failed: ${res.status}`);
      return res.json();
    },
    // used by maintenance (compaction/prune) — refs are never deletable
    async deletePack(n) {
      const res = await fetch(`${base}/packs/${n}`, { method: "DELETE", headers });
      if (!res.ok && res.status !== 404) throw new Error(`DELETE pack ${n} failed: ${res.status}`);
    }
  };
}

// src/service-worker/sw.js
var repos = /* @__PURE__ */ new Map();
var INDEX_CACHE = "egit-pack-index-v1";
function indexCacheFor(repoId) {
  const url = (id) => `${self.location.origin}/__egit_pack_index/${encodeURIComponent(repoId)}/${id}`;
  return {
    async get(id) {
      const res = await (await caches.open(INDEX_CACHE)).match(url(id));
      return res ? res.json() : null;
    },
    async put(id, index) {
      await (await caches.open(INDEX_CACHE)).put(url(id), new Response(JSON.stringify(index), {
        headers: { "content-type": "application/json" }
      }));
    }
  };
}
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("message", (event) => {
  const msg = event.data;
  if (msg?.type === "egit-set-key") {
    repos.set(msg.repoId, {
      key: Uint8Array.from(msg.keyHex.match(/../g), (h) => parseInt(h, 16)),
      base: msg.storeBaseUrl ?? `${self.location.origin}/store/${msg.repoId}`,
      headers: msg.headers ?? {}
    });
    event.ports[0]?.postMessage({ type: "egit-key-set", repoId: msg.repoId });
  }
});
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;
  const m = url.pathname.match(/^\/egit\/([^/]+)\/(repack\/)?(info\/refs|git-upload-pack|git-receive-pack)$/);
  if (!m) return;
  event.respondWith(handle(event.request, m[1], m[3], url, { repack: !!m[2] }));
});
async function handle(request, repoId, endpoint, url, options = {}) {
  try {
    const cfg = repos.get(repoId);
    if (!cfg) return new Response(`no key registered for repo ${repoId}`, { status: 403 });
    const { key } = cfg;
    const store = makeStoreClient(cfg.base, repoId, cfg.headers);
    let out;
    if (endpoint === "info/refs") {
      out = await handleInfoRefs(url.searchParams.get("service"), store, key, options);
    } else {
      const body = new Uint8Array(await request.arrayBuffer());
      const handler = endpoint === "git-upload-pack" ? handleUploadPack : handleReceivePack;
      out = await handler(body, store, key, endpoint === "git-upload-pack" ? { ...options, indexCache: self.caches ? indexCacheFor(repoId) : null } : options);
    }
    return new Response(out.body, {
      status: 200,
      headers: { "content-type": out.contentType, "cache-control": "no-cache" }
    });
  } catch (e) {
    return new Response(`egit service worker error: ${e?.stack ?? e}`, { status: 500 });
  }
}
