import { defineConfig, devices } from '@playwright/test'
import path from 'path'

export const STORAGE_STATE = path.join(__dirname, 'storageState.json')

export default defineConfig({
  testDir: './tests',
  // Installing a plugin builds and deploys microservices, which on a cold CI
  // runner is minutes rather than seconds
  timeout: 10 * 60 * 1000,
  expect: {
    timeout: 30 * 1000,
  },
  // Covers the Playwright step only: the setup budget (20 min) plus the install
  // test and its one retry. The workflow's 75 minute job timeout adds room on
  // top for checkout, the gem build and starting COSMOS, which together can
  // take 20 minutes on their own.
  globalTimeout: 40 * 60 * 1000,
  forbidOnly: !!process.env.CI,
  // COSMOS and the browser share one runner, so a starved event loop can freeze
  // a page long enough to time out an action. One retry rides that out.
  retries: process.env.CI ? 1 : 0,
  // The install spec mutates global COSMOS state, so never run specs in parallel.
  // Project dependencies ensure tool checks only run after a successful install.
  workers: 1,
  fullyParallel: false,
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    actionTimeout: 60 * 1000,
    baseURL: process.env.COSMOS_URL || 'http://localhost:2900',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    viewport: { width: 1600, height: 1200 },
  },
  projects: [
    {
      name: 'setup',
      testMatch: /auth\.setup\.ts/,
    },
    {
      name: 'install',
      testMatch: /01-install-plugin\.spec\.ts/,
      dependencies: ['setup'],
      use: {
        ...devices['Desktop Chrome'],
        storageState: STORAGE_STATE,
        viewport: { width: 1600, height: 1200 },
      },
    },
    {
      name: 'chromium',
      testMatch: /02-tool-console\.spec\.ts/,
      dependencies: ['install'],
      use: {
        ...devices['Desktop Chrome'],
        storageState: STORAGE_STATE,
        viewport: { width: 1600, height: 1200 },
      },
    },
  ],
})
