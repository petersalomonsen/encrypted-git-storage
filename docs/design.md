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

- **push:** `git pack-objects --thin --revs` (like near-git-storage) → encrypt →
  PUT `<repoId>/packs/<next>` → update the manifest (advance refs, append pack,
  bump `generation`) → CAS-write `<repoId>/refs`.
- **fetch/clone:** GET+decrypt `refs`, then GET+decrypt the packs the client needs;
  feed objects to git (`git index-pack` / a temp pack, or fast-import).

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

## Open items

- Pack compaction / GC (the append model grows; decide when to repack).
- Force-push / history rewrite semantics.
- `git-remote-egit` packaging + how the CLI user supplies the exported key.
- Confirm conditional-write support on the chosen production backend.
