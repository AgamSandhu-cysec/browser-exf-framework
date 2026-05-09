'use strict';

/**
 * Read extension id from a background or service-worker target URL, if present.
 * @param {import('puppeteer').Target} bg
 * @returns {string|null}
 */
function extensionIdFromTarget(bg) {
  const url = bg.url() || '';
  const m = url.match(/chrome-extension:\/\/([a-p]{32})\//);
  if (m) {
    return m[1];
  }
  const m2 = url.match(/chrome-extension:\/\/([a-p]{32})/);
  return m2 ? m2[1] : null;
}

/**
 * Fetch browser.targets() with a ceiling so wedged CDP cannot hang the harness.
 * @param {import('puppeteer').Browser} browser
 * @param {number} [ms=4000]
 * @returns {Promise<import('puppeteer').Target[]>}
 */
async function targetsWithTimeout(browser, ms = 4000) {
  return await Promise.race([
    browser.targets(),
    new Promise((_, reject) => setTimeout(() => reject(new Error('targets timeout')), ms)),
  ]).catch(() => []);
}

/**
 * Discover the runtime extension id from a Puppeteer browser's targets.
 * Polls until a background page or service worker appears (MV2 can be slow to register).
 * @param {import('puppeteer').Browser} browser
 * @param {number} [timeoutMs=20000]
 * @param {number} [intervalMs=200]
 * @returns {Promise<string|null>}
 */
async function discoverExtensionId(browser, timeoutMs = 20000, intervalMs = 200) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await targetsWithTimeout(browser);
    const bg = targets.find(
      (t) => t.type() === 'background_page' || t.type() === 'service_worker'
    );
    if (bg) {
      const id = extensionIdFromTarget(bg);
      if (id) {
        return id;
      }
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

/**
 * Resolve the MV2 extension background page (or null) with polling until Puppeteer attaches a Page handle.
 * @param {import('puppeteer').Browser} browser
 * @param {number} [timeoutMs=20000]
 * @param {number} [intervalMs=150]
 * @returns {Promise<import('puppeteer').Page|null>}
 */
async function getBackgroundPage(browser, timeoutMs = 20000, intervalMs = 150) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const targets = await targetsWithTimeout(browser);
    const bg = targets.find((t) => t.type() === 'background_page');
    if (bg) {
      const page = await Promise.race([
        bg.page(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('bg.page timeout')), 2500)),
      ]).catch(() => null);
      if (page) {
        return page;
      }
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

module.exports = { discoverExtensionId, getBackgroundPage, targetsWithTimeout };
