// Service worker: the browser's remote-helper equivalent — a git smart-HTTP
// "server" for wasm-git, answering from the encrypted object store.
//
// wasm-git (running in the app/worker) performs ordinary git smart-HTTP requests
// to a virtual URL under this SW's scope. The SW intercepts them and implements
// the transfer itself against the gateway proxy — encrypting packs and the refs
// manifest with ../core/crypto.js — so no smart git server is involved and the
// backend only ever sees ciphertext.
//
//   wasm-git (worker) ──/egit/<repoId>/…──> THIS SW ──/store/<repoId>/…──> gateway ──> S3
//
// All protocol logic lives in ../core/smart-http.js — shared with the node
// adapter in test/helpers/smart-server.mjs, where the REAL git CLI exercises it
// (test/gateway). This file is only fetch-event plumbing. Register as a MODULE
// service worker:
//   navigator.serviceWorker.register('/src/service-worker/sw.js', { type: 'module', scope: '/' })
//
// The AES key never leaves the client: the app configures each repo via
// postMessage (ack on ports[0]):
//
//   { type: 'egit-set-key', repoId, keyHex,
//     storeBaseUrl?,   // absolute per-repo store base (may be another origin,
//                      //   e.g. 'https://gateway.example.com/<repoId>');
//                      //   defaults to same-origin '/store/<repoId>'
//     headers? }       // extra headers on every store request — the consumer's
//                      //   auth scheme (e.g. { Authorization: 'Bearer …' });
//                      //   the gateway needs CORS (createProxy allowedOrigins)
//                      //   when storeBaseUrl is cross-origin
//
// Re-sending the message replaces the repo's config, so an app can refresh an
// expiring token without re-registering the SW. Config is in-memory only — the
// app must re-send after a SW restart.

import { handleInfoRefs, handleUploadPack, handleReceivePack } from '../core/smart-http.js';
import { makeStoreClient } from '../core/store-client.js';

const repos = new Map(); // repoId -> { key: Uint8Array(32), base: string, headers: object }

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('message', (event) => {
    const msg = event.data;
    if (msg?.type === 'egit-set-key') {
        repos.set(msg.repoId, {
            key: Uint8Array.from(msg.keyHex.match(/../g), h => parseInt(h, 16)),
            base: msg.storeBaseUrl ?? `${self.location.origin}/store/${msg.repoId}`,
            headers: msg.headers ?? {},
        });
        event.ports[0]?.postMessage({ type: 'egit-key-set', repoId: msg.repoId });
    }
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (url.origin !== self.location.origin) return;
    const m = url.pathname.match(/^\/egit\/([^/]+)\/(info\/refs|git-upload-pack|git-receive-pack)$/);
    if (!m) return; // pass through everything else (incl. this SW's own /store/* fetches)
    event.respondWith(handle(event.request, m[1], m[2], url));
});

async function handle(request, repoId, endpoint, url) {
    try {
        const cfg = repos.get(repoId);
        if (!cfg) return new Response(`no key registered for repo ${repoId}`, { status: 403 });
        const { key } = cfg;
        const store = makeStoreClient(cfg.base, repoId, cfg.headers);

        let out;
        if (endpoint === 'info/refs') {
            out = await handleInfoRefs(url.searchParams.get('service'), store, key);
        } else {
            const body = new Uint8Array(await request.arrayBuffer());
            const handler = endpoint === 'git-upload-pack' ? handleUploadPack : handleReceivePack;
            out = await handler(body, store, key);
        }
        return new Response(out.body, {
            status: 200,
            headers: { 'content-type': out.contentType, 'cache-control': 'no-cache' },
        });
    } catch (e) {
        return new Response(`egit service worker error: ${e?.stack ?? e}`, { status: 500 });
    }
}
