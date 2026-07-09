// Thin gateway proxy: authenticate the caller, then allow scoped read/write of
// `<repoId>/*` objects in the S3 bucket. The gateway never decrypts — it only sees
// ciphertext. Clients (service worker / remote helper) talk to THIS, not to S3
// directly (keeps bucket creds server-side and avoids browser→S3 CORS).
//
// Auth here is a STUB for tests (a header names the repoId). In Ariz-Portfolio this
// is replaced by the NEP-413 middleware, and repoId is derived from the account.
//
// Endpoints (suggested):
//   GET    /:repoId/refs                 -> encrypted refs manifest (404 if none)
//   PUT    /:repoId/refs                 -> set refs (with If-Match / generation CAS)
//   GET    /:repoId/packs/:n             -> encrypted packfile
//   PUT    /:repoId/packs/:n             -> store encrypted packfile
//   GET    /:repoId/packs                -> list pack indices
//
// TODO(next session): implement the routes against the S3 client, wire CAS on refs
// (If-None-Match/If-Match or versioned-object read-modify-write), stream bodies.

import express from 'express';

const PORT = process.env.PORT ?? 8080;

export function createProxy({ s3, bucket, auth } = {}) {
    const app = express();
    app.use(express.raw({ type: '*/*', limit: '100mb' }));

    // STUB auth: repoId from the `x-repo-id` header. Replace in Ariz with NEP-413.
    const resolveRepoId = auth ?? ((req) => req.header('x-repo-id') || null);

    app.use('/:repoId', (req, res, next) => {
        const repoId = resolveRepoId(req);
        if (!repoId) return res.status(401).json({ error: 'unauthorized' });
        req.repoId = repoId;
        next();
    });

    // TODO: GET/PUT refs (+CAS), GET/PUT packs, GET packs list — against `s3`/`bucket`.

    return app;
}

// Allow `npm run dev` to boot a local proxy once implemented.
if (import.meta.url === `file://${process.argv[1]}`) {
    // TODO: construct S3 client from env (see test/helpers/minio.mjs) and listen.
    console.log('gateway proxy: not implemented yet — see TODOs.');
    void PORT; void createProxy;
}
