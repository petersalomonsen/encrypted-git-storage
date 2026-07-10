// Node adapter exposing core/smart-http.js as a real HTTP git server — the exact
// role the service worker plays in the browser (sw.js is the same handlers behind
// a fetch event). Lets us drive the SW's protocol logic with the real git CLI.
//
//   git CLI ──smart HTTP──> this server ──store-client──> gateway proxy ──> MinIO
//
// URL shape: /git/<repoId>/(info/refs | git-upload-pack | git-receive-pack)
import { createServer } from 'node:http';
import { gunzipSync } from 'node:zlib';
import { handleInfoRefs, handleUploadPack, handleReceivePack } from '../../src/core/smart-http.js';
import { makeStoreClient } from '../../src/core/store-client.js';

export function createSmartServer({ proxyUrl, key }) {
    return createServer(async (req, res) => {
        try {
            const url = new URL(req.url, 'http://localhost');
            const m = url.pathname.match(/^\/git\/([^/]+)\/(info\/refs|git-upload-pack|git-receive-pack)$/);
            if (!m) { res.writeHead(404); return res.end('not found'); }
            const [, repoId, endpoint] = m;
            const store = makeStoreClient(`${proxyUrl}/${repoId}`, repoId);

            let out;
            if (endpoint === 'info/refs') {
                out = await handleInfoRefs(url.searchParams.get('service'), store, key);
            } else {
                const chunks = [];
                for await (const c of req) chunks.push(c);
                let body = Buffer.concat(chunks);
                if (req.headers['content-encoding'] === 'gzip') body = gunzipSync(body); // git gzips big bodies
                const handle = endpoint === 'git-upload-pack' ? handleUploadPack : handleReceivePack;
                out = await handle(new Uint8Array(body), store, key);
            }
            res.writeHead(200, { 'content-type': out.contentType, 'cache-control': 'no-cache' });
            res.end(Buffer.from(out.body));
        } catch (e) {
            res.writeHead(500, { 'content-type': 'text/plain' });
            res.end(String(e?.stack ?? e));
        }
    });
}
