'use strict';

/**
 * Open the extension bridge page used to call chrome.runtime.sendMessage from extension origin.
 * @param {import('puppeteer').Browser} browser
 * @param {string} extId
 * @returns {Promise<import('puppeteer').Page>}
 */
async function openBridgePage(browser, extId) {
  const page = await browser.newPage();
  await page.goto(`chrome-extension://${extId}/harness_bridge.html`, {
    waitUntil: 'domcontentloaded',
    timeout: 12000,
  });
  await page.waitForFunction(() => typeof window.__harnessSend === 'function', { timeout: 4000 });
  return page;
}

module.exports = { openBridgePage };

