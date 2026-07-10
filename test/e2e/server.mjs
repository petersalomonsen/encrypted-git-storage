// Web server for the browser e2e/interop tests — one origin serving:
//   /store/*                     the gateway proxy (ciphertext objects in MinIO)
//   /src/*, /node_modules/*      the SW + core modules + wasm-git assets
//   /                            the test page (registers the SW, drives wasm-git)
//
// The service worker is served from its real path (/src/service-worker/sw.js);
// `Service-Worker-Allowed: /` lets it claim the root scope from there.
import express from 'express';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createProxy } from '../../src/gateway/proxy.js';

const root = resolve(fileURLToPath(import.meta.url), '../../..');
const PORT = process.env.E2E_PORT ?? 8787;

export function createWebServer() {
    const app = express();
    app.use('/store', createProxy());
    app.use((req, res, next) => {
        if (req.path.endsWith('/sw.js')) res.set('Service-Worker-Allowed', '/');
        res.set('Cache-Control', 'no-store'); // tests always want fresh SW + page code
        next();
    });
    app.use(express.static(root, { index: false }));
    app.use('/', express.static(resolve(root, 'test/e2e/page')));
    return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
    createWebServer().listen(PORT, () => console.log(`e2e web server on http://127.0.0.1:${PORT}`));
}
