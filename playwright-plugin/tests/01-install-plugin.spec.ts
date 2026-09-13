/*
# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This file is licensed under the MIT license.
# See LICENSE.md file in the project root for details.
*/

// Installs the plugin gem built by the workflow through the COSMOS Admin tool,
// the same way an operator would, and verifies the install ran to completion.
//
// PLUGIN_GEM       path to the .gem file to install (required)
// EXPECTED_TARGETS space separated target names the plugin should define (optional)

import { test, expect } from '@playwright/test'
import * as fs from 'fs'
import * as path from 'path'

const gemPath = process.env.PLUGIN_GEM || ''
const gem = path.basename(gemPath)
// openc3-cosmos-kayhan-1.0.0.gem -> openc3-cosmos-kayhan
const pluginName = gem.replace(/-\d[^-]*\.gem$/, '')
const expectedTargets = (process.env.EXPECTED_TARGETS || '')
  .split(/\s+/)
  .filter(Boolean)

// The gem filename goes into a RegExp below, and plugin names are full of dots
// and dashes
function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

const escapedGem = escapeRegExp(gem)

// Installing builds and deploys the plugin's microservices, which on a cold
// runner pulling images is minutes rather than seconds
const INSTALL_TIMEOUT = 10 * 60 * 1000

test.beforeAll(() => {
  expect(gemPath, 'PLUGIN_GEM must be set').toBeTruthy()
  expect(fs.existsSync(gemPath), `${gemPath} does not exist`).toBe(true)
})

test('installs the plugin', async ({ page }) => {
  // The Complete assertion alone is allowed to burn INSTALL_TIMEOUT, so the
  // test needs headroom on top of it for the navigation, upload and submit
  test.setTimeout(INSTALL_TIMEOUT + 3 * 60 * 1000)

  await page.goto('/tools/admin/plugins')
  await expect(page.locator('.v-app-bar')).toContainText('Administrator')

  // waitForEvent must be set up before the click that opens the chooser
  const [fileChooser] = await Promise.all([
    page.waitForEvent('filechooser'),
    page.getByRole('button', { name: 'Install From File' }).click(),
  ])
  await fileChooser.setFiles(gemPath)

  // Every plugin gets the variables dialog, even with no VARIABLEs to set.
  // Submitting takes the defaults from plugin.txt.
  await expect(page.locator('.v-dialog:has-text("Variables")')).toBeVisible()
  await page.locator('data-test=edit-submit').click()

  await expect(page.locator('[data-test=plugin-alert]')).toContainText(
    'Started installing',
  )

  // Wait for the install process to report Complete. Deliberately a positive
  // assertion: the process list is only rendered once there are processes, so
  // asserting the absence of a Running row can pass before the install has even
  // been queued. A first install reports the bare gem name, a re-install
  // appends __<counter>.
  const complete = new RegExp(
    `Processing plugin_install: ${escapedGem}(__\\S+)? - Complete`,
  )
  await expect(page.locator('[data-test=process-list]')).toContainText(
    complete,
    { timeout: INSTALL_TIMEOUT },
  )

  // A failed install still leaves a process row, so confirm the plugin is
  // actually listed rather than trusting the process output alone.
  // Deliberately "at least one" and not exactly one: COSMOS names every fresh
  // install <gem>__<counter>, so a Playwright retry after an install that got
  // far enough leaves two rows, and an exact count could then never pass.
  await expect(
    page
      .locator('[data-test=plugin-list-item]')
      .filter({ hasText: pluginName })
      .first(),
  ).toBeVisible()

  for (const target of expectedTargets) {
    // Same reason as above: match "some row for this plugin lists the target"
    // rather than pinning it to a single row
    await expect(
      page
        .locator('[data-test=plugin-list-item]')
        .filter({ hasText: pluginName })
        .filter({ hasText: target })
        .first(),
      `${target} is not listed under ${pluginName}`,
    ).toBeVisible()
  }
})

test('loaded the plugin', async ({ page }) => {
  await page.goto('/tools/admin/plugins')
  await expect(page.locator('.v-app-bar')).toContainText('Administrator')

  // The show-output button only renders once the process is no longer Running,
  // which the previous test already waited for
  await page
    .locator('[data-test=process-list]')
    .locator('.v-list-item')
    .filter({ hasText: pluginName })
    .locator('[data-test=show-output]')
    .first()
    .click()

  await expect(page.getByRole('dialog')).toContainText('Process Output')
  // openc3cli logs "Loading new plugin: <path>", and the path is not always
  // just the filename, so don't anchor the gem name to the colon. On a
  // Playwright retry (or against a stack that already has the plugin) local
  // mode routes the same gem down the upgrade path, which logs
  // "Updating existing plugin: <name> with <gem>" instead.
  await expect(page.getByRole('dialog')).toContainText(
    new RegExp(`(Loading new plugin|Updating existing plugin): .*${escapedGem}`),
  )
  await page.getByRole('button', { name: 'Ok' }).click()
})
