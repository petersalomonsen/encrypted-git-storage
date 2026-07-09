import { test, expect } from '@playwright/test';

// The acceptance test: the browser (service worker) and the CLI (remote helper)
// share one encrypted store with the same key and must read each other's writes.
// Marked fixme until both sides exist.

test.fixme('interop: browser push → CLI `git clone` decrypts it', async () => {
    // 1. browser page pushes a commit via the SW
    // 2. spawn `git clone egit::<proxy>/<repoId>` with the same EGIT_KEY
    // 3. assert the CLI working tree contains the browser's commit
    expect(true).toBe(true);
});

test.fixme('interop: CLI push → browser pull decrypts it', async () => {
    // reverse direction
});
