// git smart-HTTP (protocol v0) served straight off the encrypted object store —
// the logic that lets a service worker (or any adapter) impersonate a git server
// for wasm-git / git CLI while the backend only holds ciphertext.
//
// Endpoints implemented (see git's http-protocol docs):
//   GET  .../info/refs?service=git-upload-pack | git-receive-pack
//   POST .../git-upload-pack     (fetch/clone: wants/haves -> NAK + one packfile)
//   POST .../git-receive-pack    (push: ref commands + packfile -> report-status)
//
// Deliberate simplifications, safe for a dumb single-manifest store:
//  - No capabilities that change framing (no side-band, no multi_ack, no v2):
//    clients fall back to the plainest v0 exchange.
//  - upload-pack ignores haves and serves ALL packs merged into one (packcat) —
//    correct, if not minimal; fine for the repo sizes this store targets.
//  - receive-pack requires each command's old-sha to match the manifest exactly
//    (the client already did the fast-forward ancestry check against our ref
//    advertisement); the refs-manifest CAS makes concurrent pushes safe.
//
// Env-agnostic: pass a store client (core/store-client.js) + raw key bytes.

import { encrypt, decrypt, sha256hex } from './crypto.js';
import { nextPackIndex, advanceManifest, packsInOrder } from './format.js';
import { loadManifest, encryptManifest } from './manifest-io.js';
import { pktLine, pktLines, parsePktSection, concatBytes, FLUSH } from './pktline.js';
import { concatPacks, packObjectCount } from './packcat.js';

const ZERO_SHA = '0'.repeat(40);
const CAPS = {
    'git-upload-pack': 'agent=egit/1',
    'git-receive-pack': 'report-status delete-refs agent=egit/1',
};

/** Ref advertisement lines (v0): first line carries \0capabilities. */
function advertisement(manifest, service) {
    let caps = CAPS[service];
    const entries = Object.entries(manifest.refs).sort(([a], [b]) => a < b ? -1 : 1);
    const lines = [];

    if (entries.length === 0) {
        lines.push(`${ZERO_SHA} capabilities^{}\0${caps}\n`);
        return lines;
    }
    if (service === 'git-upload-pack') {
        // HEAD first, as a symref, so clone picks the right default branch.
        const head = manifest.refs['refs/heads/main'] ? 'refs/heads/main'
            : Object.keys(manifest.refs).find(r => r.startsWith('refs/heads/'));
        if (head) {
            lines.push(`${manifest.refs[head]} HEAD\0${caps} symref=HEAD:${head}\n`);
            caps = null;
        }
    }
    for (const [name, sha] of entries) {
        lines.push(caps ? `${sha} ${name}\0${caps}\n` : `${sha} ${name}\n`);
        caps = null;
    }
    return lines;
}

/** GET info/refs?service=... -> { body, contentType } */
export async function handleInfoRefs(service, store, key) {
    if (!CAPS[service]) throw new Error(`unsupported service: ${service}`);
    const { manifest } = await loadManifest(store, key);
    const body = concatBytes(
        pktLine(`# service=${service}\n`), FLUSH,
        pktLines(advertisement(manifest, service)),
    );
    return { body, contentType: `application/x-${service}-advertisement` };
}

/** POST git-upload-pack -> { body, contentType } */
export async function handleUploadPack(reqBody, store, key) {
    // Read every pkt section; wants/haves/done can span several of them.
    const lines = [];
    for (let off = 0; off < reqBody.length;) {
        const section = parsePktSection(reqBody, off);
        lines.push(...section.lines);
        off = section.next;
    }
    const done = lines.some(l => l === 'done');
    const wants = lines.filter(l => l.startsWith('want '));

    // Pure negotiation round (no done yet): keep NAKing until the client gives up
    // adding haves — we always send the full history anyway.
    if (!done) {
        return { body: pktLine('NAK\n'), contentType: 'application/x-git-upload-pack-result' };
    }
    if (wants.length === 0) throw new Error('upload-pack: no wants');

    const { manifest } = await loadManifest(store, key);
    const packs = [];
    for (const p of packsInOrder(manifest)) {
        const pack = await decrypt(key, await store.getPack(p.n));
        if (packObjectCount(pack) > 0) packs.push(pack);
    }
    const merged = await concatPacks(packs);
    return {
        body: concatBytes(pktLine('NAK\n'), merged),
        contentType: 'application/x-git-upload-pack-result',
    };
}

/** POST git-receive-pack -> { body, contentType } */
export async function handleReceivePack(reqBody, store, key) {
    const { lines, next } = parsePktSection(reqBody);
    const packBytes = reqBody.subarray(next);
    // "<old-sha> <new-sha> <refname>" (first line carries \0capabilities — drop them)
    const commands = lines.map(l => {
        const [oldSha, newSha, ref] = l.split('\0')[0].split(' ');
        return { oldSha, newSha, ref };
    }).filter(c => c.ref);
    if (commands.length === 0) {
        // git's remote-curl PROBES with a flush-only request before streaming a
        // push body larger than http.postBuffer (1 MiB default) — answer it
        // with an empty 200 like git-http-backend, or every big CLI push dies.
        if (packBytes.length === 0) {
            return { body: new Uint8Array(0), contentType: 'application/x-git-receive-pack-result' };
        }
        throw new Error('receive-pack: no commands');
    }

    const report = (refLines) => ({
        body: pktLines(['unpack ok\n', ...refLines]),
        contentType: 'application/x-git-receive-pack-result',
    });

    // Store the pushed pack once (encrypted); reference it only if the CAS wins.
    const hasPack = packBytes.length >= 32 && packObjectCount(packBytes) > 0;
    const packMeta = hasPack
        ? { sha: await sha256hex(packBytes), size: packBytes.length }
        : null;
    const encryptedPack = hasPack ? await encrypt(key, packBytes) : null;
    let storedAt = null;

    for (let attempt = 0; attempt < 5; attempt++) {
        const { manifest, etag } = await loadManifest(store, key);

        // Every command's old-sha must match the manifest (zeros = must not exist).
        const stale = commands.filter(c => (manifest.refs[c.ref] ?? ZERO_SHA) !== c.oldSha);
        if (stale.length > 0) {
            return report(commands.map(c =>
                stale.includes(c) ? `ng ${c.ref} fetch first\n` : `ng ${c.ref} not attempted\n`));
        }

        // A push WITHOUT a packfile must not move a ref to an OID the store has
        // never seen: accepting it would advance the ref while its objects are
        // lost — every later fetch then dies with "target OID for the reference
        // doesn't exist" and the pusher never knew. Deletes and updates to an
        // OID some existing ref already carries are the only legitimate
        // pack-less commands.
        if (!packMeta) {
            const known = new Set(Object.values(manifest.refs));
            const missing = commands.filter(c => c.newSha !== ZERO_SHA && !known.has(c.newSha));
            if (missing.length > 0) {
                return report(commands.map(c => missing.includes(c)
                    ? `ng ${c.ref} push carried no packfile for new objects\n`
                    : `ng ${c.ref} not attempted\n`));
            }
        }

        let pack = null;
        if (packMeta) {
            if (storedAt === null) {
                storedAt = nextPackIndex(manifest);
                while (!(await store.putPack(storedAt, encryptedPack))) storedAt++;
            }
            pack = { n: storedAt, ...packMeta };
        }

        const refUpdates = Object.fromEntries(commands.map(c =>
            [c.ref, c.newSha === ZERO_SHA ? null : c.newSha]));
        const nextManifest = advanceManifest(manifest, { refUpdates, pack });
        if (await store.putRefs(await encryptManifest(key, nextManifest), etag)) {
            return report(commands.map(c => `ok ${c.ref}\n`));
        }
        // CAS lost — reload and re-validate old-shas (pack, if stored, is reused).
    }
    return report(commands.map(c => `ng ${c.ref} refs CAS kept failing — try again\n`));
}
