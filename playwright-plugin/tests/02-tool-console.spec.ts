/*
# Copyright 2026 OpenC3, Inc.
# All Rights Reserved.
#
# This file is licensed under the MIT license.
# See LICENSE.md file in the project root for details.
*/

// For plugins that ship a COSMOS tool, opens each tool page the plugin added and
// fails if the browser logged any error. A tool that installs cleanly can still
// be broken on load - a bad import, a missing asset, a Vue render error - and
// none of that shows up in the install process output.
//
// Plugins with no tools skip this automatically: the tool list comes from the
// COSMOS API after install, so nothing has to be declared twice.
//
// PLUGIN_GEM      path to the installed .gem (required, set by the workflow)
// IS_TOOL         'true' when the plugin is expected to register a tool
// CONSOLE_IGNORE  newline separated regexes for console errors to allow

import { test, expect, Page } from '@playwright/test'
import * as path from 'path'

const gem = path.basename(process.env.PLUGIN_GEM || '')
const pluginName = gem.replace(/-\d[^-]*\.gem$/, '')
const isTool = process.env.IS_TOOL === 'true'

// Without this an unset PLUGIN_GEM leaves pluginName as '', and the tool filter
// below ("does tool.plugin contain pluginName") then matches every tool COSMOS
// has installed, silently checking the whole product instead of this plugin
test.beforeAll(() => {
  expect(pluginName, 'PLUGIN_GEM must be set').toBeTruthy()
})

// Errors that say nothing about the plugin. Deliberately short: every entry
// here is a class of real breakage this test can no longer see.
const DEFAULT_IGNORES = [
  // Fired by the browser when a ResizeObserver callback is still running at the
  // next paint. Chromium reports it as an error, it is not one, and any Vuetify
  // layout can trip it.
  /ResizeObserver loop/,
  // The tool pages do not ship their own favicon
  /favicon\.ico/,
]

const ignores = [
  ...DEFAULT_IGNORES,
  ...(process.env.CONSOLE_IGNORE || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((pattern) => new RegExp(pattern)),
]

function ignored(message: string) {
  return ignores.some((pattern) => pattern.test(message))
}

interface Tool {
  name: string
  folder_name: string
  url: string | null
  window: string
  plugin: string | null
  shown: boolean
}

// COSMOS authenticates with a localStorage token rather than a cookie, so the
// request has to be made from inside the page
async function fetchTools(page: Page): Promise<Tool[]> {
  const result = await page.evaluate(async () => {
    const response = await fetch('/openc3-api/tools/all?scope=DEFAULT', {
      headers: { Authorization: localStorage.openc3Token },
    })
    if (!response.ok) return { error: `${response.status}` }
    return { data: await response.json() }
  })
  expect(result.error, 'could not read /openc3-api/tools/all').toBeUndefined()
  // The API returns a hash of folder_name => tool
  const data = result.data as Record<string, Tool> | Tool[]
  return Array.isArray(data) ? data : Object.values(data)
}

// Collect everything the browser complained about while the page was open
function watchForErrors(page: Page, problems: string[]) {
  page.on('console', (message) => {
    if (message.type() !== 'error') return
    const text = message.text()
    if (!ignored(text)) problems.push(`console.error: ${text}`)
  })
  page.on('pageerror', (error) => {
    const text = error.message
    if (!ignored(text)) problems.push(`uncaught: ${text}`)
  })
}

test('tool pages load without console errors', async ({ page, context }) => {
  // Any COSMOS page, just to get an authenticated origin to query from
  await page.goto('/tools/admin/plugins')
  await expect(page.locator('.v-app-bar')).toContainText('Administrator')

  const all = await fetchTools(page)
  const mine = all.filter((tool) => (tool.plugin || '').includes(pluginName))

  // WINDOW is INLINE, IFRAME, SAME or NEW (see ToolModel). Only INLINE tools are
  // mounted by COSMOS itself as a single-spa app, so only their console says
  // anything about this plugin. IFRAME embeds, and SAME (a plain link in the
  // current tab) and NEW (a new tab) navigate to, a page COSMOS doesn't render.
  const checkable = mine.filter(
    (tool) => tool.window === 'INLINE' && tool.url && tool.url.startsWith('/'),
  )

  if (mine.length === 0) {
    // A plugin that declared a tool but registered none is broken, not skippable
    expect(
      isTool,
      `is_tool is set but ${pluginName} registered no tools`,
    ).toBe(false)
    test.skip(true, `${pluginName} ships no COSMOS tools`)
    return
  }

  test.skip(
    checkable.length === 0,
    `${pluginName} ships only IFRAME/SAME/NEW tools, which render outside COSMOS`,
  )

  const failures: string[] = []
  for (const tool of checkable) {
    await test.step(`${tool.name} (${tool.url})`, async () => {
      const problems: string[] = []
      const toolPage = await context.newPage()
      watchForErrors(toolPage, problems)

      // Not networkidle: COSMOS tools poll the API and hold a cable connection
      // open, so a tool page is never reliably idle and the wait can burn the
      // whole test timeout. The settle and the 404 check below are what decide
      // whether the tool actually came up.
      await toolPage.goto(tool.url!, { waitUntil: 'domcontentloaded' })

      // Let deferred work (chunk loads, first data fetch) report itself
      await toolPage.waitForTimeout(5000)

      // tool-base renders a catch all "404 Not Found" card for a tool that
      // never registered with single-spa, and that is quiet in the console, so
      // confirm it is absent before believing a clean console means anything.
      // Deliberately not "the app bar says tool.name": a tool's title is
      // whatever its own code hands <top-bar> and does not have to equal the
      // name in plugin.txt - COSMOS's own tool is TOOL admin Admin and titles
      // itself Administrator.
      await expect(
        toolPage.getByText('404 Not Found'),
        `${tool.url} rendered tool-base's 404 instead of the tool`,
      ).toHaveCount(0)

      await toolPage.close()

      if (problems.length) {
        failures.push(`${tool.name} (${tool.url}):\n  ${problems.join('\n  ')}`)
      }
    })
  }

  // Report every tool's problems at once rather than only the first
  expect(failures.join('\n'), 'browser errors on tool pages').toBe('')
})
