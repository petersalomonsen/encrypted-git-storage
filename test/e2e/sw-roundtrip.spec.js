import { test, expect } from '@playwright/test';

// Service-worker scenario. Marked fixme until the SW + wasm-git integration and the
// gateway proxy exist (see CLAUDE.md build order). Fill these in and drop `.fixme`.

test.fixme('SW: clone → commit → push → fresh re-clone matches', async ({ page }) => {
    // 1. load test/e2e/page (registers src/service-worker/sw.js, provides the AES key)
    // 2. wasm-git: init/commit a file, `push` to egit::/<repoId> (intercepted by SW)
    // 3. clear OPFS, clone again, assert the committed file round-trips
    await page.goto('/');
    expect(true).toBe(true);
});

test.fixme('SW: the object store holds only ciphertext (zero-knowledge)', async ({ request }) => {
    // After a push, read <repoId>/packs/0 straight from MinIO and assert it is NOT a
    // valid git pack (no "PACK" magic) — i.e. isEncrypted() is true.
});
