# Design

The canonical rationale (why whole-repo encryption, why not git-crypt, the
service-worker-as-remote-helper insight, the metadata trade-offs) lives in
`arizas/Ariz-Portfolio#76`. This file records the concrete choices for *this* repo.

## Threat model

- The **object store and the gateway are untrusted** (honest-but-curious operator,
  or an attacker with store access). They must learn nothing but ciphertext sizes,
  object counts, and access timing.
- The **client is trusted** and holds the only key. In Ariz the key is derived from
  a fixed-nonce NEP-413 wallet signature via HKDF-SHA256; this library takes a raw
  32-byte key and stays agnostic to how it was produced.

## Data model (object keys)

Per opaque `<repoId>`:

```
<repoId>/refs        encrypted refs manifest   (single object, CAS-updated)
<repoId>/packs/<n>   encrypted packfile        (append-only, one per push)
```

Refs manifest (plaintext, before `core/crypto.encrypt`):

```json
{ "version": 1,
  "refs": { "refs/heads/main": "<sha>" },
  "packs": [{ "n": 0, "sha": "<sha-of-plaintext-pack>", "size": 1234 }],
  "generation": 7 }
```

## Encryption

`core/crypto.js` — AES-256-GCM via WebCrypto (Node + browser + SW). Framing:
`"EGS1" | 12-byte IV | ciphertext+tag`. Fresh random IV per object; GCM tag gives
integrity (tamper → decrypt throws). Every pack and the manifest are encrypted
independently, so incremental pushes only add one new encrypted pack.

## Push / fetch

Two transports, one store, shared `src/core`:

- **CLI (`git-remote-egit`)**
  - *push:* `git pack-objects --thin --revs` → encrypt → PUT `<repoId>/packs/<next>`
    → update the manifest (advance refs, append pack, bump `generation`) →
    CAS-write `<repoId>/refs`.
  - *fetch/clone:* GET+decrypt `refs`, then GET+decrypt every pack **in index
    order** and replay each through `git index-pack --stdin --fix-thin` (earlier
    packs provide the thin-delta bases for later ones).
- **Browser (service worker = a git smart-HTTP server)** — `core/smart-http.js`:
  - *info/refs:* advertise refs from the decrypted manifest (v0, HEAD symref,
    no side-band/multi_ack so clients use the plainest framing).
  - *upload-pack:* decrypt all packs and **merge them into one valid pack**
    (`core/packcat.js`): strip each 12-byte header + 20-byte SHA-1 trailer,
    concatenate the object sections in push order, write a summed-count header
    and a fresh SHA-1. OFS_DELTA offsets survive (relative, section-local) and
    REF_DELTA thin bases appear earlier in the merged stream, so the result is
    self-contained — verified against `git index-pack --strict` in a bare repo.
  - *receive-pack:* store the pushed pack encrypted, check each command's
    old-sha against the manifest, CAS the refs manifest (retry loop).

`test/gateway` drives the exact same smart-HTTP handlers with the real git CLI
through a small node adapter — protocol bugs reproduce there without a browser.

## Refs compare-and-set (concurrent-push safety)

Two devices pushing concurrently must not lose an update. Options, in order of
preference by backend support:

1. **Conditional write** on `<repoId>/refs`: `If-Match: <etag>` (overwrite only if
   unchanged) and `If-None-Match: "*"` (create only if absent). S3 and Cloudflare R2
   support these; recent MinIO does too. The harness test probes this.
2. **Versioned-object read-modify-write:** enable bucket versioning; on conflict
   (the `generation` in the just-written manifest isn't the one we based on), the
   loser refetches and replays. Works even without conditional writes.

The `generation` counter in the manifest makes conflicts detectable regardless.

## Backend

S3-compatible object storage (Tigris on Fly, Cloudflare R2, AWS S3, MinIO for
tests). The **gateway proxy** (`src/gateway/proxy.js`) authenticates the caller and
scopes them to their `<repoId>/*` keys, keeping bucket credentials server-side and
avoiding browser→S3 CORS. It never decrypts.

## Maintenance (compaction / GC / prune)

The append model grows by one pack per push, and a pusher that stores a pack but
loses the refs CAS leaves an orphaned `packs/<n>` behind. Three client-side ops
fix this (`core/maintenance.js`; the backend still only sees ciphertext):

- **compact** — merge every referenced pack into one via `core/packcat.js`.
  Env-agnostic (no git): the CLI runs `git-remote-egit --compact <url>`, and the
  browser can compact too. Keeps all objects, so it shrinks pack count/overhead
  but not unreachable data.
- **gc** — `git-remote-egit --gc <url>` (CLI only, needs git): replay all packs
  into a scratch bare repo, `git pack-objects --revs` from the manifest refs →
  one minimal pack. Drops objects orphaned by force-pushes/deleted branches and
  re-deltifies.
- **prune** — `git-remote-egit --prune[=mins] <url>`: delete stored packs the
  manifest doesn't reference, age-guarded via the store's lastModified (default
  60 min) so an in-flight push's pack (CAS not yet landed) is never swept.

Both compact and gc go through a CAS-safe swap (`replacePacks`): write the merged
pack at a fresh index, CAS the manifest to reference only it, THEN delete the
superseded packs; on CAS conflict (concurrent push) delete the merged pack and
retry. A reader holding a pre-compaction manifest can hit a deleted pack (404) —
it should reload the manifest and retry.

**Force-push semantics:** allowed and tested on both transports. The CLI helper
checks fast-forward locally (skipped with `+`/`--force`); smart-HTTP receive-pack
requires each command's old-sha to match the manifest exactly (concurrency
safety — the ff check is the client's job in v0). Rewritten-away objects remain
in the store until `--gc`. A forced move to an existing commit (or a new branch
at one) is a ref-only manifest update — no pack is stored.

## Open items

- `git-remote-egit` packaging + how the CLI user supplies the exported key.
- Confirm conditional-write support on the chosen production backend (MinIO
  enforces both `If-None-Match: *` and `If-Match` on PUT — verified by tests).
- Automatic compaction policy (e.g. compact when pack count exceeds N) — the
  mechanism exists; deciding when to trigger it is a consumer concern.
- Possible later: a Rust `git-remote-egit` as a single static binary (nicer CLI
  distribution — no Node needed). The format is now frozen and policed by
  `test/cli` + `test/gateway` + `test/interop`, so a second implementation can be
  validated by pointing those suites at the Rust binary on PATH. The gateway
  stays in Node either way — it holds no logic (auth + streaming proxy, never
  decrypts) and Ariz swaps in its NEP-413 middleware there.
