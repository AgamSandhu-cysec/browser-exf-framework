'use strict';

const { emitFinding } = require('../utils/finding_emitter.js');
const { getBackgroundPage } = require('../utils/extension_loader.js');
const { openBridgePage } = require('../utils/bridge_page.js');

/**
 * Probe dangerous background message handling.
 * @param {import('puppeteer').Browser} browser
 * @param {string} extId
 * @param {string} baseUrl
 * @param {() => number} getCanaryHits
 * @param {() => number} getCanaryJsHits
 * @returns {Promise<void>}
 */
async function runBackgroundInjectorTests(browser, extId, baseUrl, getCanaryHits, getCanaryJsHits) {
  const bridge = await openBridgePage(browser, extId);
  const bgPage = await getBackgroundPage(browser, 8000, 100);
  const canaryPageUrl = `${baseUrl}/canary`;
  const canaryJsUrl = `${baseUrl}/canary.js`;

  const payloads = [
    { code: 'globalThis.__bg_injected=true' },
    { action: 'storage_dump' },
    { scriptUrl: canaryJsUrl },
    { type: 'open_tab', url: canaryPageUrl },
  ];

  try {
    for (const payload of payloads) {
      const hitsBefore = getCanaryHits();
      const jsBefore = getCanaryJsHits();
      const pagesBefore = (await browser.pages()).length;

      await bridge.evaluate((msg) => {
        return new Promise((resolve) => {
          try {
            window.__harnessSend(msg, () => resolve(true));
          } catch (e) {
            resolve(false);
          }
        });
      }, payload);

      await new Promise((r) => setTimeout(r, 1500));

      let injected = false;
      if (bgPage) {
        injected = await bgPage
          .evaluate(() => globalThis.__bg_injected === true || self.__bg_injected === true)
          .catch(() => false);
      }
      const hitsAfter = getCanaryHits();
      const jsAfter = getCanaryJsHits();
      const pagesAfter = (await browser.pages()).length;

      if (injected || hitsAfter > hitsBefore || jsAfter > jsBefore || pagesAfter > pagesBefore) {
        emitFinding({
          module: 'dynamic_background_injector',
          severity: 'critical',
          title: 'Background message handler allows dangerous effects (dynamic)',
          description:
            'Runtime messaging produced observable code execution, remote script load, canary network activity, or new tab creation.',
          evidence: JSON.stringify({
            payload,
            injected,
            hitsBefore,
            hitsAfter,
            jsBefore,
            jsAfter,
            pagesBefore,
            pagesAfter,
          }),
          file: '[runtime]',
          line: null,
          remediation: 'Validate sender and message schema; remove eval and arbitrary URL/tab actions.',
          cwe: 'CWE-94',
          confidence: 0.96,
          poc_type: 'background_injection',
          poc_payload: JSON.stringify(payload),
        });
        break;
      }
    }
  } catch (err) {
    process.stderr.write(`background_injector: ${String(err)}\n`);
  } finally {
    await bridge.close().catch(() => {});
  }
}

module.exports = { runBackgroundInjectorTests };
