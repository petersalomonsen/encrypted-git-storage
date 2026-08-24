// git smart-HTTP (protocol v0) served straight off the encrypted object store —
// the logic that lets a service worker (or any adapter) impersonate a git server
// for wasm-git / git CLI while the backend only holds ciphertext.
//
// Endpoints implemented (see git's http-protocol docs):
//   GET  .../info/refs?service=git-upload-pack | git-receive-pack
//   POST .../git-upload-pack     (fetch/clone: wants/haves -> NAK + one packfile)
//   POST .../git-receive-pack    (push: ref commands + packfile -> report-status)
//
// The two push endpoints also serve a REPACK ({ repack: true }) — which exists
// because of what upload-pack does; see "Overlapping packs" below.
//
// Deliberate simplifications, safe for a dumb single-manifest store:
//  - No capabilities that change framing (no side-band, no multi_ack, no v2):
//    clients fall back to the plainest v0 exchange.
//  - upload-pack ignores haves and serves ALL packs merged into one (packcat).
//  - receive-pack requires each command's old-sha to match the manifest exactly
//    (the client already did the fast-forward ancestry check against our ref
//    advertisement); the refs-manifest CAS makes concurrent pushes safe.
//
// Overlapping packs
// -----------------
// Merging every pack into one is valid only while no object is in two of them,
// and nothing guarantees that: a client pushing a MERGE commit re-sends the
// subtrees and blobs its merged tree shares with the side the store already
// holds. From then on the merged pack carries the same object twice.
//
// The git CLI indexes such a pack without complaining. libgit2 — i.e. wasm-git,
// this store's whole reason to exist — refuses it:
//
//     duplicate object <oid> found in pack
//
// and because a failed fetch never creates the remote-tracking ref, the client
// reports the confusing pair "revspec 'origin/master' not found" and then a
// rejected push. One merge push and no browser can read the store again.
// (Diagnosed on a real store: 89 objects in two packs, all from one merge push.
// The CLI tests never saw it because the CLI does not care.)
//
// Nothing here can drop the duplicate: telling two copies apart needs each
// object's id, which needs the deltas resolved, which is index-pack — not
// something a service worker carries. So the fix is to stop the store
// accumulating overlapping packs, and the one participant that can build a
// clean pack is the client, which has a real git. That is what a repack is:
// the client is told the store has no refs, so it builds a COMPLETE pack, and
// the store swaps its pack list for that one pack while leaving every ref
// exactly where it was. Refs never move, so a repack cannot lose history, and
// the packs it supersedes are left for pruneOrphans (core/maintenance.js)
// rather than deleted, so a bad one is still recoverable.
//
// Env-agnostic: pass a store client (core/store-client.js) + raw key bytes.

import { encrypt, decrypt, sha256hex } from './crypto.js';
import { MANIFEST_VERSION, nextPackIndex, advanceManifest, packsInOrder } from './format.js';
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

/**
 * GET info/refs?service=... -> { body, contentType }
 *
 * @param {{repack?: boolean}} [options] repack: advertise NO refs, so the client
 *   packs its whole history instead of an increment. Push only.
 */
export async function handleInfoRefs(service, store, key, { repack = false } = {}) {
    if (!CAPS[service]) throw new Error(`unsupported service: ${service}`);
    if (repack && service !== 'git-receive-pack') {
        throw new Error(`repack is a push: ${service} is not available on it`);
    }
    const { manifest } = await loadManifest(store, key);
    const advertised = repack ? { ...manifest, refs: {} } : manifest;
    const body = concatBytes(
        pktLine(`# service=${service}\n`), FLUSH,
        pktLines(advertisement(advertised, service)),
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

    // Pure negotiation round (no done yet): keep NAKing until the client gives up
    // adding haves — we always send the full history anyway.
    if (!done) {
        return { body: pktLine('NAK\n'), contentType: 'application/x-git-upload-pack-result' };
    }

    // The want list is deliberately not checked. A negotiation spans several
    // POSTs and only the FIRST carries the wants: once the client stops adding
    // wants it sends the next batch of `have`s plus `done`, and nothing else.
    // Rejecting that round for "no wants" turned it into a 500 whose body git
    // read as a packfile — reported as "bad packet length", from the client's
    // point of view an unreadable store. It only bit a client with enough local
    // history to need a second round, so clones always worked and fetches from a
    // device that had committed locally did not.

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
export async function handleReceivePack(reqBody, store, key, { repack = false } = {}) {
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

        if (repack) {
            // The client was told the store has no refs, so it offers to CREATE
            // every ref at the sha the store already holds. Anything else — a
            // different sha, a ref the store does not have, a ref left out — is
            // not a repack, and taking it would move a ref on the strength of an
            // advertisement that was deliberately a fiction. Refuse instead.
            const wrong = commands.filter(c => c.newSha !== manifest.refs[c.ref]);
            const missing = Object.keys(manifest.refs).filter(ref => !commands.some(c => c.ref === ref));
            if (wrong.length > 0 || missing.length > 0) {
                return report([
                    ...commands.map(c => wrong.includes(c)
                        ? `ng ${c.ref} repack must offer the store's current tip — fetch first\n`
                        : `ng ${c.ref} not attempted\n`),
                    ...missing.map(ref => `ng ${ref} repack must cover every ref\n`),
                ]);
            }
            if (!packMeta) {
                return report(commands.map(c => `ng ${c.ref} repack carried no packfile\n`));
            }

            if (storedAt === null) {
                storedAt = nextPackIndex(manifest);
                while (!(await store.putPack(storedAt, encryptedPack))) storedAt++;
            }
            // Refs unchanged: a repack rewrites storage, never history. The
            // superseded packs are left in place for pruneOrphans to sweep,
            // so this is reversible for as long as that window lasts.
            const repacked = {
                version: MANIFEST_VERSION,
                refs: manifest.refs,
                packs: [{ n: storedAt, ...packMeta }],
                generation: manifest.generation + 1,
            };
            if (await store.putRefs(await encryptManifest(key, repacked), etag)) {
                return report(commands.map(c => `ok ${c.ref}\n`));
            }
            continue; // CAS lost to a concurrent push — re-validate and retry
        }

        // Every command's old-sha must match the manifest (zeros = must not exist).
        const stale = commands.filter(c => (manifest.refs[c.ref] ?? ZERO_SHA) !== c.oldSha);
        if (stale.length > 0) {
            return report(commands.map(c =>
                stale.includes(c) ? `ng ${c.ref} fetch first\n` : `ng ${c.ref} not attempted\n`));
        }

        // A push whose body carries NO pack section at all must not move a ref
        // to an OID the store has never seen: accepting it would advance the
        // ref while its objects are lost — every later fetch then dies with
        // "target OID for the reference doesn't exist" and the pusher never
        // knew. Zero-OBJECT packs are different and legitimate: git sends one
        // for ref-only updates whose objects the server already has (e.g. a
        // force-back to an earlier commit) — without connectivity checks a
        // dumb encrypted store cannot validate those, and rejecting them
        // breaks real git, so only the missing-pack-section case is guarded.
        if (packBytes.length === 0) {
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
