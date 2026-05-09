'use strict';

const path = require('path');
const puppeteer = require('puppeteer');

/**
 * Launch Chrome with the unpacked extension loaded (extensions require headed mode).
 * @param {string} extPath Absolute path to unpacked extension directory
 * @param {string} userDataDir Ephemeral profile directory (avoids SingletonLock clashes between runs)
 * @returns {Promise<import('puppeteer').Browser>}
 */
async function launchBrowserWithExtension(extPath, userDataDir) {
  const resolved = path.resolve(extPath);
  const args = [
    `--user-data-dir=${userDataDir}`,
    `--disable-extensions-except=${resolved}`,
    `--load-extension=${resolved}`,
    '--no-sandbox',
    '--disable-gpu',
    '--window-size=1,1',
  ];
  const browser = await puppeteer.launch({
    headless: false,
    args,
    defaultViewport: { width: 1, height: 1 },
  });
  return browser;
}

module.exports = { launchBrowserWithExtension };
