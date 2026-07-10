# encrypted-git-storage — agent context

You are working on **encrypted-git-storage**: a reusable library that lets a
[wasm-git](https://github.com/petersalomonsen/wasm-git) app (and a regular git
CLI) sync a git repository to a **dumb object store** with the **whole repo
encrypted client-side** — the storage backend only ever sees ciphertext.

It is the encrypted, object-storage counterpart of
[`near-git-storage`](https://github.com/petersalomonsen/near-git-storage) (which
stores packfiles on the NEAR blockchain). Same shape — a **service worker** for
the browser and a **git remote helper** for the CLI, both writing/reading the
same store — but here the backend is S3-compatible object storage and every
packfile + the refs manifest is AES-encrypted with a client-held key.

## Why / where it's used

It was designed for **Ariz-Portfolio** to sync sensitive data (confidential NEAR
intents transactions) to its gateway zero-knowledge. The design and rationale
live in two issues on that repo — **read them, they are the source of truth**:

- `arizas/Ariz-Portfolio#76` — whole-repo client-side encryption (this project's spec, with the architecture diagram).
- `arizas/Ariz-Portfolio#75` — the confidential-transactions consumer.

This repo is intentionally **generic** (no portfolio/NEAR-auth specifics). Ariz
integration (NEP-413 auth on the gateway, wallet-derived key) happens back in
Ariz-Portfolio — do that work there, not here.

## The core idea (how a service worker replaces a remote helper)

A git **remote helper** is a client-side shim that turns `git push`/`fetch` into
encrypted-blob storage against a dumb backend: build a packfile → encrypt → store;
reverse on fetch. In the browser, a **service worker** plays that exact role — it
**intercepts wasm-git's git-smart-HTTP requests** (`info/refs`,
`git-upload-pack`, `git-receive-pack`) and implements the transfer itself against
the store. No smart git server exists. `near-git-storage` already ships both a SW
and a `git-remote-near` CLI helper over one `{refs, packs}` key-value store — copy
that structure, swap the backend for object storage, and add encryption.

```
Browser: wasm-git + OPFS ──git smart-HTTP(intercepted)──> Service Worker ─┐
                                                                          ├─> gateway proxy ─> S3 object store
CLI:     git ──remote-helper protocol──> git-remote-egit ─────────────────┘        (only ciphertext)

  client-held AES key (derived from a wallet signature in Ariz; a raw key here)
  encrypts every packfile + the refs manifest before it leaves the client.
```

## Store model (dumb, S3-compatible)

Per repo (namespaced by an opaque `<repoId>`), object keys:

- `` <repoId>/packs/<n> `` — an **encrypted** packfile (one per push; append model like near-git-storage).
- `` <repoId>/refs `` — the **encrypted** refs manifest (branch/tag → SHA, pack list). Updated with a **compare-and-set** so concurrent pushes can't lose updates.

The backend never parses git and never sees plaintext. Residual metadata: number
of packs, each pack's size, and push timing.

## Repository layout

```
src/
  core/            shared, backend- and environment-agnostic
    crypto.js        AES-256-GCM encrypt/decrypt; key handling            [DONE]
    format.js        refs-manifest (de)serialization + push helpers       [DONE]
    pktline.js       git pkt-line framing (protocol v0)                   [DONE]
    packcat.js       merge append-only packs into ONE valid pack          [DONE]
    store-client.js  gateway client (refs CAS + packs), fetch-based       [DONE]
    smart-http.js    git smart-HTTP served off the encrypted store        [DONE]
    manifest-io.js   load/save the encrypted manifest via a store client  [DONE]
    maintenance.js   compact (browser-capable) / replacePacks / prune     [DONE]
  service-worker/
    sw.js            fetch-event plumbing around core/smart-http.js       [DONE]
  remote-helper/
    git-remote-egit.js   git remote-helper protocol (stdin/stdout)        [DONE]
  gateway/
    proxy.js         thin auth proxy in front of S3 (stub auth here;      [DONE]
                     Ariz replaces stub auth with NEP-413). Also the
                     S3 client wrapper (put/get/list/CAS).
test/
  storage/         object-store harness vs MinIO (put/get/list/CAS)       [passing]
  core/            crypto + format + pktline + packcat unit tests         [passing]
  cli/             git + git-remote-egit + proxy + MinIO scenario         [passing]
  gateway/         REAL git CLI over smart HTTP (the SW's protocol        [passing]
                   logic via a node adapter) + cross-transport interop
  e2e/             Playwright: wasm-git behind the SW (+ server.mjs,      [passing]
                   page/ with the module worker driving wasm-git)
  interop/         browser<->CLI cross round-trip with repo growth       [passing]
  helpers/         MinIO client + smart-server adapter + fixtures
docs/design.md     full design (mirrors Ariz #76) + format spec
.github/workflows/ci.yml   MinIO + Playwright + node tests
```

## Build order (TDD)

1. ✅ **`test/storage`** passes and proves the CI object-storage harness
   (MinIO put/get/list/delete, and conditional writes — both `If-None-Match: *`
   and `If-Match` — used for refs-CAS). Keep it green.
2. ✅ **`src/core/crypto.js` + `format.js`** — the encrypted pack + refs format. Unit-tested round-trips.
3. ✅ **`src/gateway/proxy.js`** S3 wrapper (put/get/list + CAS on `refs`).
4. ✅ **`src/remote-helper/git-remote-egit.js`** — `test/cli` passes (real `git` + the Node helper + proxy + MinIO), including the ciphertext (zero-knowledge) assertion and stale-push rejection.
5. ✅ **`src/service-worker/sw.js`** — `test/e2e` (Playwright) passes: wasm-git (OPFS auto-loader,
   JSPI variant in CI chromium) in a module worker, all git smart-HTTP intercepted by the SW.
   The protocol logic lives in `src/core/smart-http.js` and is ALSO driven by the real git CLI
   in `test/gateway` via the node adapter (`test/helpers/smart-server.mjs`) — debug protocol
   issues there first, it's much faster than the browser loop.
6. ✅ **`test/interop`** — browser↔CLI both directions with repo growth (multiple commits from
   each side, ~3MB binaries verified by hash, incremental fetch, one pack per push).
7. ✅ Ciphertext assertions on every path (`test/cli`, `test/gateway`, `test/e2e`, `test/interop`):
   packs read straight from MinIO are never valid git packs and leak no ref names.

All build-order steps are done, plus hardening: force-push/history-rewrite
semantics (both transports), pack compaction (`git-remote-egit --compact`, also
runnable from the browser), reachability GC (`--gc`), orphan pruning (`--prune`),
and tamper-detection tests (GCM). See docs/design.md "Maintenance" for the ops
and their CAS-safety story; remaining open items are listed there (packaging,
auto-compaction policy, optional Rust helper).

## Key references

- near-git-storage (the SW + remote-helper + dumb-store template): https://github.com/petersalomonsen/near-git-storage
- wasm-git (libgit2 in the browser): https://github.com/petersalomonsen/wasm-git
- git-remote-gcrypt (whole-repo encryption remote helper, prior art): https://github.com/spwhitton/git-remote-gcrypt
- git remote-helper protocol: `git help remote-helpers`
- Ariz issues (spec + consumer): arizas/Ariz-Portfolio#76, #75

## Conventions

- Node ESM. `npm test` runs the node test suites; `npm run test:e2e` runs Playwright.
- Keep `src/core` free of Node- or browser-only APIs so both the SW and the CLI helper share it (use WebCrypto — available in Node as `globalThis.crypto` and in the browser/SW). Node ≥22 (`node --test` glob patterns need ≥21; Node 20 is EOL).
- No secrets in the repo. MinIO test creds are the well-known `minioadmin` dev defaults, CI-only.
