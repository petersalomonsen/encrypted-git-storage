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
        baseURL: 'http://127.0.0.1:8080',
        headless: true,
        trace: 'retain-on-failure',
    },
    projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

    // TODO(next session): boot the gateway proxy (src/gateway/proxy.js) + a static
    // server for test/e2e/page so the SW + wasm-git can run against MinIO.
    // webServer: {
    //   command: 'node src/gateway/proxy.js',
    //   port: 8080,
    //   reuseExistingServer: !process.env.CI,
    // },
});
