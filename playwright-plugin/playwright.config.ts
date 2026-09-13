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
  globalTimeout: 30 * 60 * 1000,
  forbidOnly: !!process.env.CI,
  // COSMOS and the browser share one runner, so a starved event loop can freeze
  // a page long enough to time out an action. One retry rides that out.
  retries: process.env.CI ? 1 : 0,
  // The install spec mutates global COSMOS state, so never run specs in parallel.
  // Specs are numbered because the later ones need the plugin the first one
  // installed, and Playwright runs files in discovery order.
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
      name: 'chromium',
      testIgnore: /auth\.setup\.ts/,
      dependencies: ['setup'],
      use: {
        ...devices['Desktop Chrome'],
        storageState: STORAGE_STATE,
        viewport: { width: 1600, height: 1200 },
      },
    },
  ],
})
