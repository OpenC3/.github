/*
# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This file is licensed under the MIT license.
# See LICENSE.md file in the project root for details.
*/

// Signs in to a freshly started COSMOS Core and saves the session for the specs.
//
// Login.vue asks /openc3-api/auth/token-exists on load. A container that has
// never been used has no password, so it renders the "set a password" form
// (New Password + Confirm Password + Set), which is the CI case. A container
// that already has one renders a single Password field and a Login button. The
// password field carries data-test=new-password either way, so key off whether
// the confirm field is present rather than off the labels, which change text
// between the two states.

import { test as setup, expect, Page } from '@playwright/test'
import { STORAGE_STATE } from '../playwright.config'

const PASSWORD = process.env.COSMOS_PASSWORD || 'password'

// init.sh installs the tools one at a time, so the admin tool being present in
// the import map is the signal that COSMOS is far enough along to drive. A tool
// that isn't in the map is never registered with single-spa and tool-base
// renders its 404 instead, which a spec only sees as a missing app bar.
async function waitForAdminTool(page: Page) {
  await expect
    .poll(
      async () => {
        try {
          const response = await page.request.get('/openc3-api/map.json')
          if (!response.ok()) return false
          const imports = (await response.json()).imports || {}
          return '@openc3/tool-admin' in imports
        } catch {
          return false
        }
      },
      {
        message: 'waiting for @openc3/tool-admin in the import map',
        timeout: 12 * 60 * 1000,
        intervals: [5000],
      },
    )
    .toBe(true)
}

setup('sign in', async ({ page }) => {
  setup.setTimeout(20 * 60 * 1000)

  await waitForAdminTool(page)

  await page.goto('/tools/cmdtlmserver')

  // The password form is rendered by tool-base once it decides we're not
  // authenticated, which can lag the initial load
  await expect(page.locator('[data-test=new-password]')).toBeVisible({
    timeout: 60 * 1000,
  })
  await page.locator('[data-test=new-password]').fill(PASSWORD)

  if (await page.locator('[data-test=confirm-password]').isVisible()) {
    // First run, COSMOS wants the password created
    await page.locator('[data-test=confirm-password]').fill(PASSWORD)
    await page.locator('[data-test=set-password]').click()
  } else {
    // A password already exists, e.g. re-running against a stack still up
    await page.locator('button:has-text("Login")').click()
  }

  // Confirm the session actually works rather than trusting the form submit
  await expect(page.locator('.v-app-bar')).toContainText('CmdTlmServer', {
    timeout: 2 * 60 * 1000,
  })

  if (await page.getByText('Clock out of sync').isVisible()) {
    await page.locator("text=Don't show this again").click()
    await page.locator('button:has-text("Dismiss")').click()
  }

  await page.context().storageState({ path: STORAGE_STATE })
})
