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
//
// The data-test attributes sit on the v-text-field, which Vuetify renders as a
// wrapper div around the real <input>. Playwright can only fill the input, so
// fill() has to reach inside the wrapper.

import { test as setup, expect, Page } from '@playwright/test'
import { STORAGE_STATE } from '../playwright.config'

const PASSWORD = process.env.COSMOS_PASSWORD || 'password'

// init.sh installs the plugins one at a time, so a tool appearing in the import
// map only means init.sh got that far. A tool that isn't in the map is never
// registered with single-spa and tool-base renders its 404 instead, which a
// spec only sees as a missing app bar.
//
// The marker has to be the LAST inline tool init.sh loads, not the first one we
// happen to need: tool-admin is loaded well before the demo plugin and before
// cmdtlmserver, so waiting on admin would let the specs start while INST/INST2
// don't exist yet and /tools/cmdtlmserver still 404s. bucketexplorer is the
// last tool init.sh loads that gets an import map entry (docs is iframe based),
// which is the same marker the COSMOS repo's own suite waits on.
const READY_MARKER = '@openc3/tool-bucketexplorer'

async function waitForTools(page: Page) {
  await expect
    .poll(
      async () => {
        try {
          const response = await page.request.get('/openc3-api/map.json')
          if (!response.ok()) return false
          const imports = (await response.json()).imports || {}
          return READY_MARKER in imports
        } catch {
          return false
        }
      },
      {
        message: `waiting for ${READY_MARKER} in the import map`,
        timeout: 12 * 60 * 1000,
        intervals: [5000],
      },
    )
    .toBe(true)
}

setup('sign in', async ({ page }) => {
  setup.setTimeout(20 * 60 * 1000)

  await waitForTools(page)

  await page.goto('/tools/cmdtlmserver')

  // The password form is rendered by tool-base once it decides we're not
  // authenticated, which can lag the initial load
  await expect(page.locator('[data-test=new-password]')).toBeVisible({
    timeout: 60 * 1000,
  })
  await page.locator('[data-test=new-password] input').fill(PASSWORD)

  if (await page.locator('[data-test=confirm-password]').isVisible()) {
    // First run, COSMOS wants the password created
    await page.locator('[data-test=confirm-password] input').fill(PASSWORD)
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
