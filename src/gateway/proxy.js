// Thin gateway proxy: authenticate the caller, then allow scoped read/write of
// `<repoId>/*` objects in the S3 bucket. The gateway never decrypts — it only sees
// ciphertext. Clients (service worker / remote helper) talk to THIS, not to S3
// directly (keeps bucket creds server-side and avoids browser→S3 CORS).
//
// Auth here is a STUB for tests (a header names the repoId). In Ariz-Portfolio this
// is replaced by the NEP-413 middleware, and repoId is derived from the account.
//
// Endpoints:
//   GET    /:repoId/refs        -> encrypted refs manifest + ETag (404 if none)
//   PUT    /:repoId/refs        -> CAS write: requires If-Match: <etag> (update)
//                                  or If-None-Match: * (create); 412 on conflict,
//                                  428 if no condition given (no blind clobbers)
//   GET    /:repoId/packs       -> JSON list of stored pack indices
//   GET    /:repoId/packs/:n    -> encrypted packfile
//   PUT    /:repoId/packs/:n    -> store encrypted packfile (create-only; packs
//                                  are immutable — 412 if the index is taken)

import express from 'express';
import {
    S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand,
} from '@aws-sdk/client-s3';

const PORT = process.env.PORT ?? 8080;

/** S3 client from env — same conventions as test/helpers/minio.mjs (MinIO dev defaults). */
export function s3FromEnv() {
    return new S3Client({
        endpoint: process.env.S3_ENDPOINT ?? 'http://127.0.0.1:9000',
        region: process.env.S3_REGION ?? 'us-east-1',
        forcePathStyle: true,
        credentials: {
            accessKeyId: process.env.S3_ACCESS_KEY ?? 'minioadmin',
            secretAccessKey: process.env.S3_SECRET_KEY ?? 'minioadmin',
        },
    });
}

const isPreconditionFailure = (e) =>
    e?.$metadata?.httpStatusCode === 412 || e?.name === 'PreconditionFailed';
const isMissing = (e) =>
    e?.$metadata?.httpStatusCode === 404 || e?.name === 'NoSuchKey' || e?.name === 'NotFound';

export function createProxy({ s3 = s3FromEnv(), bucket = process.env.S3_BUCKET ?? 'egit-test', auth } = {}) {
    const app = express();
    app.use(express.raw({ type: '*/*', limit: '100mb' }));

    // STUB auth: repoId from the `x-repo-id` header. Replace in Ariz with NEP-413.
    const resolveRepoId = auth ?? ((req) => req.header('x-repo-id') || null);

    app.use('/:repoId', (req, res, next) => {
        const repoId = resolveRepoId(req);
        if (!repoId) return res.status(401).json({ error: 'unauthorized' });
        if (repoId !== req.params.repoId) return res.status(403).json({ error: 'forbidden' });
        req.repoId = repoId;
        next();
    });

    const sendObject = async (res, key) => {
        try {
            const r = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
            res.set('ETag', r.ETag).type('application/octet-stream');
            res.send(Buffer.from(await r.Body.transformToByteArray()));
        } catch (e) {
            if (isMissing(e)) return res.status(404).json({ error: 'not found' });
            throw e;
        }
    };

    app.get('/:repoId/refs', (req, res, next) =>
        sendObject(res, `${req.repoId}/refs`).catch(next));

    // CAS write of the refs manifest. The condition headers map 1:1 onto S3
    // conditional PutObject (verified against MinIO by test/storage).
    app.put('/:repoId/refs', async (req, res, next) => {
        try {
            const ifMatch = req.header('if-match');
            const ifNoneMatch = req.header('if-none-match');
            if (!ifMatch && ifNoneMatch !== '*') {
                return res.status(428).json({ error: 'refs writes require If-Match or If-None-Match: *' });
            }
            const r = await s3.send(new PutObjectCommand({
                Bucket: bucket, Key: `${req.repoId}/refs`, Body: req.body,
                ...(ifMatch ? { IfMatch: ifMatch } : { IfNoneMatch: '*' }),
            }));
            res.set('ETag', r.ETag).status(204).end();
        } catch (e) {
            if (isPreconditionFailure(e)) return res.status(412).json({ error: 'refs changed — refetch and retry' });
            next(e);
        }
    });

    // Every stored pack, referenced by the manifest or not — with lastModified
    // so maintenance can age-guard orphan pruning.
    app.get('/:repoId/packs', async (req, res, next) => {
        try {
            const prefix = `${req.repoId}/packs/`;
            const r = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }));
            const packs = (r.Contents ?? [])
                .map(o => ({
                    n: Number(o.Key.slice(prefix.length)),
                    size: o.Size,
                    lastModified: new Date(o.LastModified).getTime(),
                }))
                .filter(p => Number.isInteger(p.n))
                .sort((a, b) => a.n - b.n);
            res.json(packs);
        } catch (e) { next(e); }
    });

    app.get('/:repoId/packs/:n(\\d+)', (req, res, next) =>
        sendObject(res, `${req.repoId}/packs/${req.params.n}`).catch(next));

    // Packs are immutable and append-only: create-only so a racing pusher can
    // never overwrite someone else's pack (it gets 412 and picks the next index).
    app.put('/:repoId/packs/:n(\\d+)', async (req, res, next) => {
        try {
            await s3.send(new PutObjectCommand({
                Bucket: bucket, Key: `${req.repoId}/packs/${req.params.n}`,
                Body: req.body, IfNoneMatch: '*',
            }));
            res.status(204).end();
        } catch (e) {
            if (isPreconditionFailure(e)) return res.status(412).json({ error: 'pack index taken' });
            next(e);
        }
    });

    // Maintenance (compaction / orphan-prune) removes superseded packs. Only
    // packs are deletable — never the refs manifest.
    app.delete('/:repoId/packs/:n(\\d+)', async (req, res, next) => {
        try {
            await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: `${req.repoId}/packs/${req.params.n}` }));
            res.status(204).end();
        } catch (e) { next(e); }
    });

    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => {
        console.error('[gateway]', err);
        res.status(500).json({ error: 'internal error' });
    });

    return app;
}

// `npm run dev` boots a local proxy against env-configured S3 (MinIO defaults).
if (import.meta.url === `file://${process.argv[1]}`) {
    createProxy().listen(PORT, () => console.log(`gateway proxy listening on :${PORT}`));
}
