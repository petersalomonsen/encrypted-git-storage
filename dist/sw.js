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

// src/core/packcat.js
var PACK_MAGIC = 1346454347;
function header(view) {
  if (view.byteLength < 32) throw new Error("pack too small");
  const dv = new DataView(view.buffer, view.byteOffset, view.byteLength);
  if (dv.getUint32(0) !== PACK_MAGIC) throw new Error("bad pack magic");
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
  const head = new Uint8Array(12);
  const dv = new DataView(head.buffer);
  dv.setUint32(0, PACK_MAGIC);
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
async function handleInfoRefs(service, store, key) {
  if (!CAPS[service]) throw new Error(`unsupported service: ${service}`);
  const { manifest } = await loadManifest(store, key);
  const body = concatBytes(
    pktLine(`# service=${service}
`),
    FLUSH,
    pktLines(advertisement(manifest, service))
  );
  return { body, contentType: `application/x-${service}-advertisement` };
}
async function handleUploadPack(reqBody, store, key) {
  const lines = [];
  for (let off = 0; off < reqBody.length; ) {
    const section = parsePktSection(reqBody, off);
    lines.push(...section.lines);
    off = section.next;
  }
  const done = lines.some((l) => l === "done");
  const wants = lines.filter((l) => l.startsWith("want "));
  if (!done) {
    return { body: pktLine("NAK\n"), contentType: "application/x-git-upload-pack-result" };
  }
  if (wants.length === 0) throw new Error("upload-pack: no wants");
  const { manifest } = await loadManifest(store, key);
  const packs = [];
  for (const p of packsInOrder(manifest)) {
    const pack = await decrypt(key, await store.getPack(p.n));
    if (packObjectCount(pack) > 0) packs.push(pack);
  }
  const merged = await concatPacks(packs);
  return {
    body: concatBytes(pktLine("NAK\n"), merged),
    contentType: "application/x-git-upload-pack-result"
  };
}
async function handleReceivePack(reqBody, store, key) {
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
  const m = url.pathname.match(/^\/egit\/([^/]+)\/(info\/refs|git-upload-pack|git-receive-pack)$/);
  if (!m) return;
  event.respondWith(handle(event.request, m[1], m[2], url));
});
async function handle(request, repoId, endpoint, url) {
  try {
    const cfg = repos.get(repoId);
    if (!cfg) return new Response(`no key registered for repo ${repoId}`, { status: 403 });
    const { key } = cfg;
    const store = makeStoreClient(cfg.base, repoId, cfg.headers);
    let out;
    if (endpoint === "info/refs") {
      out = await handleInfoRefs(url.searchParams.get("service"), store, key);
    } else {
      const body = new Uint8Array(await request.arrayBuffer());
      const handler = endpoint === "git-upload-pack" ? handleUploadPack : handleReceivePack;
      out = await handler(body, store, key);
    }
    return new Response(out.body, {
      status: 200,
      headers: { "content-type": out.contentType, "cache-control": "no-cache" }
    });
  } catch (e) {
    return new Response(`egit service worker error: ${e?.stack ?? e}`, { status: 500 });
  }
}
