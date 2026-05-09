'use strict';

const { emitFinding } = require('../utils/finding_emitter.js');

/** @type {string[]} */
const XSS_PAYLOADS = [
  '<img src=x onerror="window.__xss_fired=\'img\'">',
  '<svg onload="window.__xss_fired=\'svg\'">',
  '"><script>window.__xss_fired="script"<\/script>',
  "'><img src=x onerror=window.__xss_fired='quote'>",
  'javascript:window.__xss_fired=1',
];

/** @type {string[]} */
const POSITIONS = ['title', 'h1', 'meta', 'dataAttr', 'inputValue'];

/**
 * Encode payload for query string (base64url).
 * @param {string} s
 * @returns {string}
 */
function toB64Url(s) {
  return Buffer.from(s, 'utf8').toString('base64url');
}

/**
 * Poll until window.__xss_fired is truthy or timeout.
 * @param {import('puppeteer').Page} page
 * @param {number} maxMs
 * @returns {Promise<string|false>}
 */
async function waitForXssFlag(page, maxMs) {
  const deadline = Date.now() + maxMs;
  while (Date.now() < deadline) {
    const v = await page.evaluate(() => window.__xss_fired || false);
    if (v) {
      return String(v);
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/**
 * Run one XSS probe for a single DOM position.
 * @param {import('puppeteer').Browser} browser
 * @param {string} baseUrl
 * @param {string} payload
 * @param {string} pos
 * @returns {Promise<void>}
 */
async function probePosition(browser, baseUrl, payload, pos) {
  const page = await browser.newPage();
  try {
    await page.goto(
      `${baseUrl}/xss?pos=${encodeURIComponent(pos)}&p=${encodeURIComponent(toB64Url(payload))}`,
      {
        waitUntil: 'domcontentloaded',
        timeout: 12000,
      }
    );
    const fired = await waitForXssFlag(page, 2000);
    if (fired) {
      emitFinding({
        module: 'dynamic_xss',
        severity: 'critical',
        title: 'Content script XSS (dynamic)',
        description: `XSS payload executed via reflected ${pos} sink (marker: ${fired}).`,
        evidence: `position=${pos}; marker=${fired}`,
        file: '[runtime]',
        line: null,
        remediation: 'Encode or sanitize all page-controlled data before assigning to innerHTML or similar sinks.',
        cwe: 'CWE-79',
        confidence: 0.95,
        poc_type: 'content_script_xss',
        poc_payload: payload,
        poc_description: `Serve payload in ${pos} field and observe window.__xss_fired.`,
      });
    }
  } finally {
    await page.close().catch(() => {});
  }
}

/**
 * Run fragment-hash XSS probe for one payload.
 * @param {import('puppeteer').Browser} browser
 * @param {string} baseUrl
 * @param {string} payload
 * @returns {Promise<void>}
 */
async function probeFragment(browser, baseUrl, payload) {
  const fragPage = await browser.newPage();
  try {
    const enc = encodeURIComponent(payload);
    await fragPage.goto(`${baseUrl}/blank#${enc}`, {
      waitUntil: 'domcontentloaded',
      timeout: 12000,
    });
    const firedFrag = await waitForXssFlag(fragPage, 2000);
    if (firedFrag) {
      emitFinding({
        module: 'dynamic_xss',
        severity: 'critical',
        title: 'Content script XSS via URL fragment (dynamic)',
        description: `XSS fired from location.hash reflection (marker: ${firedFrag}).`,
        evidence: `fragment payload; marker=${firedFrag}`,
        file: '[runtime]',
        line: null,
        remediation: 'Never assign location.hash to innerHTML without strict validation.',
        cwe: 'CWE-79',
        confidence: 0.95,
        poc_type: 'content_script_xss',
        poc_payload: payload,
        poc_description: 'Navigate to /blank#URLENCODED_PAYLOAD',
      });
    }
  } finally {
    await fragPage.close().catch(() => {});
  }
}

/**
 * Run content-script XSS probes against the local test server.
 * Uses parallel probes per payload so the module stays within the global harness budget.
 * @param {import('puppeteer').Browser} browser
 * @param {string} baseUrl
 * @returns {Promise<void>}
 */
async function runXssTests(browser, baseUrl) {
  for (const payload of XSS_PAYLOADS) {
    const positionTasks = POSITIONS.map((pos) => probePosition(browser, baseUrl, payload, pos));
    const fragmentTask = probeFragment(browser, baseUrl, payload);
    await Promise.all([...positionTasks, fragmentTask]);
  }
}

module.exports = { runXssTests, XSS_PAYLOADS };
