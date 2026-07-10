// Minimal S3 client for tests, pointed at MinIO (CI) or any S3-compatible store.
// Reads connection details from env with dev-only defaults matching the MinIO
// service started in .github/workflows/ci.yml.
import {
    S3Client, CreateBucketCommand, HeadBucketCommand,
    PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand
} from '@aws-sdk/client-s3';

export const S3_ENDPOINT = process.env.S3_ENDPOINT ?? 'http://127.0.0.1:9000';
export const S3_BUCKET = process.env.S3_BUCKET ?? 'egit-test';

export function makeClient() {
    return new S3Client({
        endpoint: S3_ENDPOINT,
        region: process.env.S3_REGION ?? 'us-east-1',
        forcePathStyle: true, // MinIO needs path-style addressing
        credentials: {
            accessKeyId: process.env.S3_ACCESS_KEY ?? 'minioadmin',
            secretAccessKey: process.env.S3_SECRET_KEY ?? 'minioadmin',
        },
    });
}

// True if the store is reachable — tests skip gracefully when it isn't (e.g. a
// dev machine with no MinIO running). CI always has MinIO up.
export async function storeReachable(client = makeClient(), timeoutMs = 1500) {
    try {
        await Promise.race([
            client.send(new ListObjectsV2Command({ Bucket: S3_BUCKET, MaxKeys: 1 })).catch(() => {}),
            new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs)),
        ]);
        // A missing bucket still means the endpoint answered.
        const res = await fetch(`${S3_ENDPOINT}/minio/health/ready`).catch(() => null);
        return !!res && res.ok;
    } catch {
        return false;
    }
}

export async function ensureBucket(client = makeClient(), bucket = S3_BUCKET) {
    try {
        await client.send(new HeadBucketCommand({ Bucket: bucket }));
    } catch {
        try {
            await client.send(new CreateBucketCommand({ Bucket: bucket }));
        } catch (e) {
            // Test files run in parallel; on a fresh store several race to create
            // the bucket and the losers get 409 — that still means "bucket exists".
            if (!['BucketAlreadyOwnedByYou', 'BucketAlreadyExists'].includes(e?.Code ?? e?.name)) throw e;
        }
    }
}

export const put = (client, Key, Body, extra = {}) =>
    client.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key, Body, ...extra }));

export async function getBytes(client, Key) {
    const res = await client.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key }));
    return Buffer.from(await res.Body.transformToByteArray());
}

export async function list(client, Prefix) {
    const res = await client.send(new ListObjectsV2Command({ Bucket: S3_BUCKET, Prefix }));
    return (res.Contents ?? []).map(o => o.Key);
}

export const del = (client, Key) =>
    client.send(new DeleteObjectCommand({ Bucket: S3_BUCKET, Key }));
