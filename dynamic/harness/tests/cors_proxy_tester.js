'use strict';

const { emitFinding } = require('../utils/finding_emitter.js');
const { openBridgePage } = require('../utils/bridge_page.js');
const { CORS_PROBE_BODY } = require('../utils/page_factory.js');

/**
 * Ask the extension (via bridge) to fetch a URL and return the serialized response.
 * @param {import('puppeteer').Page} bridge
 * @param {string} url
 * @param {number} timeoutMs
 * @returns {Promise<unknown>}
 */
async function extensionFetchViaRuntime(bridge, url, timeoutMs) {
  return await Promise.race([
    bridge.evaluate((u) => {
      return new Promise((resolve) => {
        try {
          window.__harnessSend({ type: 'fetch', url: u }, (resp) => {
            if (chrome.runtime.lastError) {
              resolve({ error: chrome.runtime.lastError.message });
            } else {
              resolve(resp);
            }
          });
        } catch (e) {
          resolve({ error: String(e) });
        }
      });
    }, url),
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
  ]).catch((e) => ({ error: String(e) }));
}

/**
 * Probe whether the extension proxies cross-origin fetch via runtime messaging.
 * @param {import('puppeteer').Browser} browser
 * @param {string} extId
 * @param {string} [crossOriginProbeUrl] Second localhost origin (no public internet required)
 * @returns {Promise<void>}
 */
async function runCorsProxyTests(browser, extId, crossOriginProbeUrl) {
  const bridge = await openBridgePage(browser, extId);
  try {
    /** @type {string[]} */
    const urls = [];
    if (crossOriginProbeUrl) {
      urls.push(crossOriginProbeUrl);
    }
    urls.push('https://httpbin.org/get');

    for (const url of urls) {
      const result = await extensionFetchViaRuntime(bridge, url, url.includes('httpbin') ? 3500 : 8000);
      const blob = JSON.stringify(result).slice(0, 4000);
      const dataStr = result && result.data ? String(result.data) : '';
      const hitLocal = Boolean(crossOriginProbeUrl && url === crossOriginProbeUrl && dataStr.includes(CORS_PROBE_BODY));
      const hitHttpbin =
        blob.toLowerCase().includes('httpbin') || dataStr.toLowerCase().includes('httpbin');
      if (hitLocal || hitHttpbin) {
        emitFinding({
          module: 'dynamic_cors_proxy',
          severity: 'high',
          title: 'Extension proxies cross-origin fetch (dynamic)',
          description: hitLocal
            ? 'Runtime messaging returned HTTP body from a different local origin, indicating fetch proxy / CORS-bypass capability.'
            : 'Runtime messaging returned remote HTTP body from httpbin.org, indicating fetch proxy / CORS-bypass capability.',
          evidence: blob,
          file: '[runtime]',
          line: null,
          remediation: 'Do not forward arbitrary URLs through the extension; enforce strict URL allowlists.',
          cwe: 'CWE-346',
          confidence: 0.92,
          poc_type: 'cors_proxy',
          poc_payload: JSON.stringify({ type: 'fetch', url }),
        });
        return;
      }
    }
  } catch (err) {
    process.stderr.write(`cors_proxy_tester: ${String(err)}\n`);
  } finally {
    await bridge.close().catch(() => {});
  }
}

module.exports = { runCorsProxyTests };
