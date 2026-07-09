// Service worker: the browser's remote-helper equivalent.
//
// wasm-git (running in the app/worker) performs ordinary git smart-HTTP requests
// to a virtual URL under this SW's scope. The SW intercepts them and implements the
// transfer itself against the gateway proxy — encrypting packs and the refs
// manifest with ../core/crypto.js — so no smart git server is involved and the
// backend only ever sees ciphertext.
//
// Model this on near-git-storage's service worker (which does the same, translating
// to NEAR RPC instead of an encrypted object store).
//
// Requests to intercept (under e.g. /egit/<repoId>/...):
//   GET  .../info/refs?service=git-upload-pack   -> ref advertisement from manifest
//   POST .../git-upload-pack                      -> serve requested objects (decrypt packs, build a pack)
//   GET  .../info/refs?service=git-receive-pack   -> ref advertisement
//   POST .../git-receive-pack                     -> receive client's pack, encrypt, store, CAS refs
//
// TODO(next session): implement fetch() handler + the smart-HTTP framing. The AES
// key is provided by the app via postMessage (Ariz derives it from the wallet).

const SCOPE_PREFIX = '/egit/';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (!url.pathname.startsWith(SCOPE_PREFIX)) return; // pass through everything else
    // TODO: route info/refs, git-upload-pack, git-receive-pack -> core + gateway proxy.
    event.respondWith(new Response('git-over-encrypted-store: not implemented yet', { status: 501 }));
});
