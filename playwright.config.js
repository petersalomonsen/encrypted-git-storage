// @ts-check
import { defineConfig, devices } from '@playwright/test';

// E2E covers the service-worker + interop scenarios. `testDir` holds only *.spec.js
// (node --test owns *.test.mjs, so the two runners don't overlap).
export default defineConfig({
    testDir: './test',
    testMatch: /.*\.spec\.js/,
    timeout: 30_000,
    fullyParallel: false,
    forbidOnly: !!process.env.CI,
    retries: process.env.CI ? 2 : 0,
    reporter: 'line',
    use: {
        baseURL: 'http://127.0.0.1:8787',
        headless: true,
        trace: 'retain-on-failure',
    },
    projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

    // One origin: test page + SW + core modules + wasm-git assets + the gateway
    // proxy under /store (which fronts MinIO — must be running, as in CI).
    webServer: {
        command: 'node test/e2e/server.mjs',
        port: 8787,
        reuseExistingServer: !process.env.CI,
    },
});
