'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { launchBrowserWithExtension } = require('./setup.js');
const { discoverExtensionId } = require('./utils/extension_loader.js');
const { createTestServer } = require('./utils/page_factory.js');
const { resetFindings, getFindings } = require('./utils/finding_emitter.js');
const { runXssTests } = require('./tests/xss_tester.js');
const { runPostmessageTests } = require('./tests/postmessage_monitor.js');
const { runCorsProxyTests } = require('./tests/cors_proxy_tester.js');
const { runBackgroundInjectorTests } = require('./tests/background_injector.js');

const MODULE_TIMEOUT_MS = 30000;
const TOTAL_TIMEOUT_MS = 120000;

/** @type {import('puppeteer').Browser|null} */
let browserRef = null;

/** @type {string|null} */
let userDataDirRef = null;

/**
 * Close localhost / about harness pages left open after a timed-out module
 * so browser.close() does not wait on hung navigations.
 * @param {import('puppeteer').Browser} browser
 * @returns {Promise<void>}
 */
async function closeOrphanHarnessPages(browser) {
  /** @type {import('puppeteer').Page[]} */
  let pages;
  try {
    pages = await Promise.race([
      browser.pages(),
      new Promise((resolve) => setTimeout(() => resolve([]), 4000)),
    ]);
  } catch (_e) {
    return;
  }
  if (!pages.length) {
    return;
  }
  for (const p of pages) {
    let u = '';
    try {
      u = p.url() || '';
    } catch (_e2) {
      continue;
    }
    if (
      u.startsWith('http://127.0.0.1:') ||
      u.startsWith('http://localhost:') ||
      u === 'about:blank'
    ) {
      await p.close().catch(() => {});
    }
  }
}

/**
 * Force-close the browser on process signals.
 * @returns {void}
 */
function shutdownOnSignal() {
  if (browserRef) {
    forceCloseBrowser(browserRef).catch(() => {});
  }
}

/**
 * Close the browser with a bounded wait, then SIGKILL the Chrome process (extension tests may open tabs).
 * Avoids calling browser.pages() which can deadlock on wedged Chrome.
 * @param {import('puppeteer').Browser} browser
 * @returns {Promise<void>}
 */
async function forceCloseBrowser(browser) {
  try {
    await Promise.race([
      browser.close(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('browser.close timeout')), 8000)),
    ]);
  } catch (_err) {
    const proc = browser.process();
    if (proc && !proc.killed) {
      proc.kill('SIGKILL');
    }
  }
}

process.on('SIGTERM', shutdownOnSignal);
process.on('SIGINT', shutdownOnSignal);

/**
 * Parse --ext-path from argv.
 * @returns {string}
 */
function parseExtPath() {
  const idx = process.argv.indexOf('--ext-path');
  if (idx === -1 || !process.argv[idx + 1]) {
    process.stderr.write('runner.js: missing --ext-path argument\n');
    process.exit(2);
  }
  return process.argv[idx + 1];
}

/**
 * Run an async function with a hard per-module timeout.
 * @template T
 * @param {string} label
 * @param {() => Promise<T>} fn
 * @param {number} ms
 * @returns {Promise<T>}
 */
async function runWithTimeout(label, fn, ms) {
  return await Promise.race([
    fn(),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
    ),
  ]);
}

/**
 * Execute all harness modules and print JSON findings to stdout.
 * @returns {Promise<void>}
 */
async function main() {
  const extPath = parseExtPath();
  resetFindings();
  const started = Date.now();

  /** @type {Awaited<ReturnType<typeof createTestServer>>|null} */
  let serverCtx = null;

  try {
    process.stderr.write('runner.js: starting harness\n');
    userDataDirRef = fs.mkdtempSync(path.join(os.tmpdir(), 'ext-attack-harness-'));
    browserRef = await launchBrowserWithExtension(extPath, userDataDirRef);
    process.stderr.write('runner.js: chrome launched\n');
    const extId = await discoverExtensionId(browserRef);
    if (!extId) {
      process.stderr.write('runner.js: could not discover extension id\n');
      process.stdout.write(JSON.stringify([]) + '\n');
      return;
    }
    process.stderr.write(`runner.js: discovered extId=${extId}\n`);

    serverCtx = await createTestServer();
    process.stderr.write('runner.js: test servers started\n');
    const { baseUrl, crossOriginProbeUrl, getCanaryHits, getCanaryJsHits, close } = serverCtx;

    const modules = [
      ['xss_tester', () => runXssTests(browserRef, baseUrl)],
      ['postmessage_monitor', () => runPostmessageTests(browserRef, baseUrl, getCanaryHits)],
      ['cors_proxy_tester', () => runCorsProxyTests(browserRef, extId, crossOriginProbeUrl)],
      [
        'background_injector',
        () => runBackgroundInjectorTests(browserRef, extId, baseUrl, getCanaryHits, getCanaryJsHits),
      ],
    ];

    for (const [name, runnerFn] of modules) {
      if (Date.now() - started > TOTAL_TIMEOUT_MS) {
        process.stderr.write('runner.js: global 120s budget exceeded; stopping modules.\n');
        break;
      }
      try {
        process.stderr.write(`runner.js: module ${name} start\n`);
        await runWithTimeout(name, runnerFn, MODULE_TIMEOUT_MS);
        process.stderr.write(`runner.js: module ${name} done\n`);
      } catch (err) {
        process.stderr.write(`runner.js: module ${name} failed: ${String(err)}\n`);
        if (browserRef) {
          await closeOrphanHarnessPages(browserRef);
        }
      }
    }
  } catch (err) {
    process.stderr.write(`runner.js: fatal: ${String(err)}\n`);
  } finally {
    process.stderr.write('runner.js: entering cleanup\n');
    if (serverCtx) {
      try {
        process.stderr.write('runner.js: closing servers\n');
        await serverCtx.close();
        process.stderr.write('runner.js: servers closed\n');
      } catch (e) {
        process.stderr.write(`runner.js: server close: ${String(e)}\n`);
      }
    }
    if (browserRef) {
      try {
        process.stderr.write('runner.js: closing browser\n');
        await forceCloseBrowser(browserRef);
        process.stderr.write('runner.js: browser closed\n');
      } catch (e) {
        process.stderr.write(`runner.js: browser close: ${String(e)}\n`);
      }
      browserRef = null;
    }
    if (userDataDirRef) {
      try {
        fs.rmSync(userDataDirRef, { recursive: true, force: true });
      } catch (_e) {
        // temp cleanup best-effort
      }
      userDataDirRef = null;
    }
    process.stderr.write('runner.js: cleanup complete\n');
  }

  process.stdout.write(JSON.stringify(getFindings()) + '\n');
}

main().catch((e) => {
  process.stderr.write(`runner.js: unhandled: ${String(e)}\n`);
  process.stdout.write(JSON.stringify([]) + '\n');
  process.exit(1);
});
