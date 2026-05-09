'use strict';

const { emitFinding } = require('../utils/finding_emitter.js');

/**
 * Install postMessage logging on a page before navigation.
 * @param {import('puppeteer').Page} page
 * @returns {Promise<void>}
 */
async function installPostMessageTap(page) {
  await page.evaluateOnNewDocument(() => {
    window.__pm_log = [];
    window.addEventListener('message', (e) => {
      try {
        window.__pm_log.push({
          origin: e.origin,
          data: JSON.stringify(e.data).slice(0, 500),
        });
      } catch (_err) {
        window.__pm_log.push({ origin: e.origin, data: '[unserializable]' });
      }
    });
  });
}

/**
 * @param {string} dataStr
 * @returns {boolean}
 */
function containsSensitiveKeyword(dataStr) {
  const lower = dataStr.toLowerCase();
  return ['token', 'cookie', 'auth', 'password', 'key', 'secret'].some((k) => lower.includes(k));
}

/**
 * Run postMessage monitoring and attack-surface probes.
 * @param {import('puppeteer').Browser} browser
 * @param {string} baseUrl
 * @param {() => number} getCanaryHits
 * @returns {Promise<void>}
 */
async function runPostmessageTests(browser, baseUrl, getCanaryHits) {
  const page = await browser.newPage();
  try {
    await installPostMessageTap(page);
    await page.goto(`${baseUrl}/blank`, { waitUntil: 'domcontentloaded', timeout: 25000 });
    await new Promise((r) => setTimeout(r, 2000));
    const log = await page.evaluate(() => window.__pm_log || []);
    for (const entry of log) {
      const blob = `${entry.origin} ${entry.data}`;
      if (containsSensitiveKeyword(blob)) {
        emitFinding({
          module: 'dynamic_postmessage',
          severity: 'high',
          title: 'Extension broadcasts sensitive data via postMessage',
          description: 'Observed postMessage traffic containing credential-like keywords.',
          evidence: blob.slice(0, 800),
          file: '[runtime]',
          line: null,
          remediation: 'Never postMessage secrets; restrict targetOrigin and strip sensitive fields.',
          cwe: 'CWE-201',
          confidence: 0.85,
          poc_type: 'postmessage_injection',
          poc_payload: entry.data,
        });
        break;
      }
    }

    const canaryUrl = `${baseUrl}/canary`;
    const payloads = [
      { type: 'exec', code: 'window.__injected=true' },
      { type: 'eval', script: 'document.cookie' },
      { type: 'fetch', url: 'https://httpbin.org/get', callback: true },
      { action: 'navigate', url: canaryUrl },
      { __proto__: { polluted: true }, type: 'sync' },
    ];

    for (const pl of payloads) {
      const canaryBefore = getCanaryHits();
      await page.evaluate((p) => {
        window.postMessage(p, '*');
      }, pl);
      await new Promise((r) => setTimeout(r, 1000));
      const injected = await page.evaluate(() => window.__injected === true);
      const canaryAfter = getCanaryHits();
      if (injected || canaryAfter > canaryBefore) {
        emitFinding({
          module: 'dynamic_postmessage',
          severity: 'high',
          title: 'postMessage attack surface confirmed (dynamic)',
          description:
            'A synthetic postMessage produced an observable effect (DOM script execution and/or canary hit).',
          evidence: JSON.stringify(pl).slice(0, 800),
          file: '[runtime]',
          line: null,
          remediation: 'Validate event.origin; reject unexpected senders; never eval message payloads.',
          cwe: 'CWE-94',
          confidence: 0.9,
          poc_type: 'postmessage_injection',
          poc_payload: JSON.stringify(pl),
        });
        break;
      }
    }
  } finally {
    await page.close().catch(() => {});
  }
}

module.exports = { runPostmessageTests, installPostMessageTap };
