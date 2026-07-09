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

> Status: **scaffold.** The object-store test harness runs; the git/encryption
> plumbing is TODO. See [`CLAUDE.md`](./CLAUDE.md) for the design, build order, and
> agent context, and [`docs/design.md`](./docs/design.md) for detail.

## Why

Built so apps can back up sensitive data to an untrusted server zero-knowledge.
Origin/spec: `arizas/Ariz-Portfolio` issues **#76** (this design) and **#75** (the
confidential-transactions consumer).

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

npm test           # node --test: core crypto + object-store harness (+ cli when built)
npm run test:e2e   # Playwright: service-worker + interop (when built)
```

Without a reachable store the object-store tests **skip** (they don't fail). CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) starts MinIO so they run.

## License

MIT
