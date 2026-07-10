// Client for the gateway proxy's object endpoints, shared by the CLI remote
// helper and the service worker. Only ever carries ciphertext. Env-agnostic:
// uses global fetch (Node 20+, browser, SW).
//
// Auth is the gateway's concern; the stub gateway keys off `x-repo-id`. Extra
// headers (e.g. Ariz's NEP-413 auth) can be layered via `headers`.

export function makeStoreClient(base, repoId, extraHeaders = {}) {
    const headers = { 'x-repo-id': repoId, 'content-type': 'application/octet-stream', ...extraHeaders };
    return {
        // -> { bytes, etag } | null when absent
        async getRefs() {
            const res = await fetch(`${base}/refs`, { headers });
            if (res.status === 404) return null;
            if (!res.ok) throw new Error(`GET refs failed: ${res.status}`);
            return { bytes: new Uint8Array(await res.arrayBuffer()), etag: res.headers.get('etag') };
        },
        // CAS write: etag=null means create-if-absent. -> true | false on 412 conflict
        async putRefs(bytes, etag) {
            const res = await fetch(`${base}/refs`, {
                method: 'PUT', body: bytes,
                headers: { ...headers, ...(etag ? { 'if-match': etag } : { 'if-none-match': '*' }) },
            });
            if (res.status === 412) return false;
            if (!res.ok) throw new Error(`PUT refs failed: ${res.status}`);
            return true;
        },
        async getPack(n) {
            const res = await fetch(`${base}/packs/${n}`, { headers });
            if (!res.ok) throw new Error(`GET pack ${n} failed: ${res.status}`);
            return new Uint8Array(await res.arrayBuffer());
        },
        // create-only (packs are immutable). -> true | false when the index is taken
        async putPack(n, bytes) {
            const res = await fetch(`${base}/packs/${n}`, { method: 'PUT', body: bytes, headers });
            if (res.status === 412) return false;
            if (!res.ok) throw new Error(`PUT pack ${n} failed: ${res.status}`);
            return true;
        },
        // every stored pack (whether the manifest references it or not)
        // -> [{ n, size, lastModified (epoch ms) }]
        async listPacks() {
            const res = await fetch(`${base}/packs`, { headers });
            if (!res.ok) throw new Error(`GET packs failed: ${res.status}`);
            return res.json();
        },
        // used by maintenance (compaction/prune) — refs are never deletable
        async deletePack(n) {
            const res = await fetch(`${base}/packs/${n}`, { method: 'DELETE', headers });
            if (!res.ok && res.status !== 404) throw new Error(`DELETE pack ${n} failed: ${res.status}`);
        },
    };
}
