# encrypted-git-storage

Sync a git repository to a **dumb object store** with the **whole repo encrypted
client-side**. The storage backend (S3-compatible object storage) only ever sees
ciphertext — no filenames, no history, no contents. Two clients, one store:

- a **browser service worker** that intercepts [wasm-git](https://github.com/petersalomonsen/wasm-git)'s git traffic, and
- a **git remote helper** (`git-remote-egit`) for a regular `git clone`/`push`.

It's the encrypted, object-storage sibling of
[`near-git-storage`](https://github.com/petersalomonsen/near-git-storage): same
service-worker + remote-helper shape, but the packfiles and refs manifest are
AES-256-GCM encrypted with a client-held key, and the backend is object storage
instead of the NEAR blockchain.

> Status: **working.** Both transports round-trip against MinIO in CI — including
> browser↔CLI interop with multi-MB binaries, force-pushes, and client-side
> compaction/GC. See [`docs/design.md`](./docs/design.md) for the format and
> design detail, [`CLAUDE.md`](./CLAUDE.md) for agent context.

## Why

Built so apps can back up sensitive data to an untrusted server zero-knowledge.
Origin/spec: `arizas/Ariz-Portfolio` issues **#76** (this design) and **#75** (the
confidential-transactions consumer).

## Consuming

Install as a git dependency (no npm registry publish yet):

```sh
npm install github:petersalomonsen/encrypted-git-storage#v0.1.1
```

npm runs the package's `prepare` script on git installs, so the bundled service
worker `dist/sw.js` is built for you inside `node_modules`. (In a plain checkout,
`npm install` does the same; `npm run build` rebuilds it.)

### Gateway (Node)

```js
import { createProxy } from 'encrypted-git-storage/gateway';

// S3 client + bucket from env (S3_ENDPOINT, S3_BUCKET, …) — or pass your own:
// createProxy({ s3, bucket, auth: (req) => authenticatedRepoIdOrNull(req) })
createProxy().listen(8080);
```

The default `auth` is a test stub (`x-repo-id` header). Replace it — that's where
Ariz-Portfolio plugs in NEP-413.

### Browser (service worker + wasm-git)

Serve `node_modules/encrypted-git-storage/dist/sw.js` from your app (it's a
single self-contained ESM file) and register it; hand it the repo key, then point
[wasm-git](https://github.com/petersalomonsen/wasm-git) at `/egit/<repoId>`:

```js
await navigator.serviceWorker.register('/sw.js', { type: 'module', scope: '/' });
await navigator.serviceWorker.ready;

// give the SW the client-held AES key for this repo (MessageChannel ack)
const ch = new MessageChannel();
const ack = new Promise((res) => { ch.port1.onmessage = res; });
navigator.serviceWorker.controller.postMessage(
  { type: 'egit-set-key', repoId, keyHex }, [ch.port2]);
await ack;

// wasm-git then clones/pushes over ordinary git smart HTTP:
//   http://<your-origin>/egit/<repoId>   (SW ⇄ gateway at /store/<repoId>)
```

By default the SW expects the gateway on the same origin under `/store`. See
[`test/e2e/page`](test/e2e/page) for a complete working page + worker.

### Cross-origin stores + auth

When the app page and the gateway live on different origins (e.g. the page on
`arizportfolio.near.page`, the gateway on `arizgateway.fly.dev`), point the SW at
the foreign store and attach your auth scheme per repo — re-send the same message
any time to refresh an expiring token, no re-registration needed:

```js
navigator.serviceWorker.controller.postMessage({
  type: 'egit-set-key', repoId, keyHex,
  storeBaseUrl: `https://arizgateway.fly.dev/${repoId}`, // absolute, per-repo
  headers: { Authorization: `Bearer ${token}` },         // on every store request
}, [ch.port2]);
```

The gateway must then allow the page's origin (cross-origin PUTs with an
`Authorization` header always preflight; `ETag` is exposed for the refs CAS):

```js
createProxy({
  allowedOrigins: ['https://arizportfolio.near.page'],
  auth: (req) => verifyYourToken(req.header('authorization')), // → repoId | null
}).listen(8080);
```

The CLI helper sends the same header via env:

```sh
export EGIT_AUTH="Bearer <token>"   # Authorization on every store request
git clone egit::https://arizgateway.fly.dev/<repoId>
```

The library stays auth-agnostic — it only carries the headers. Token issuance
and verification (NEP-413 in Ariz) are the consumer's, on both ends.

### CLI

```sh
npm install -g github:petersalomonsen/encrypted-git-storage#v0.1.1  # puts git-remote-egit on PATH
export EGIT_KEY=<64 hex chars>   # the 32-byte repo key

git clone egit::https://gateway.example.com/store/<repoId>
git push  egit::https://gateway.example.com/store/<repoId> main

git-remote-egit --compact <gateway>/store/<repoId>   # merge packs (no git needed — browser can too)
git-remote-egit --gc      <gateway>/store/<repoId>   # drop unreachable objects, redeltify
git-remote-egit --prune   <gateway>/store/<repoId>   # sweep orphaned packs (age-guarded)
```

### Core primitives

```js
import { encrypt, decrypt, isEncrypted, makeStoreClient, compact }
  from 'encrypted-git-storage/core';
```

Everything under `/core` is environment-agnostic (WebCrypto + fetch): the same
code runs in the service worker, the browser, and Node.

## Layout

| Path | What |
|---|---|
| `src/core/` | shared AES-GCM crypto + store format (browser + Node) |
| `src/service-worker/` | browser: intercept git smart-HTTP → encrypt → store |
| `src/remote-helper/` | CLI: `git-remote-egit` |
| `src/gateway/` | thin auth proxy in front of the object store |
| `test/storage/` | **runnable** object-store harness (MinIO/S3) |
| `test/{e2e,cli,interop}/` | service-worker / remote-helper / cross-interop scenarios |

## Develop

```sh
npm install

# object-store tests need an S3 endpoint; run MinIO locally:
docker run -d -p 9000:9000 -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data

npm test           # node --test: core, storage harness, CLI + smart-HTTP (real git), packaging
npm run test:e2e   # Playwright: wasm-git behind the service worker + browser↔CLI interop
```

Without a reachable store the object-store tests **skip** (they don't fail). CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) starts MinIO so they run.

## License

MIT
