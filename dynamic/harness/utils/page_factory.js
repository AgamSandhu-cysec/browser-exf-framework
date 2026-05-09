'use strict';

const http = require('http');
const { URL } = require('url');

/** Distinctive body returned by the secondary-origin probe server (CORS-proxy test). */
const CORS_PROBE_BODY = 'HARNESS_CORS_LEAK_BODY';

/**
 * Decode a base64url-encoded UTF-8 string.
 * @param {string} encoded
 * @returns {string}
 */
function decodePayload(encoded) {
  if (!encoded) {
    return '';
  }
  const pad = encoded.length % 4 === 0 ? '' : '='.repeat(4 - (encoded.length % 4));
  const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(b64, 'base64').toString('utf8');
}

/**
 * Escape text for embedding inside HTML text nodes (minimal — harness-controlled payloads only).
 * @param {string} s
 * @returns {string}
 */
function escapeHtmlText(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Build HTML document that injects the XSS payload into the requested DOM slot.
 * @param {string} position
 * @param {string} payloadRaw
 * @returns {string}
 */
function buildXssHtml(position, payloadRaw) {
  const p = payloadRaw;
  let title = 'safe';
  let h1 = '';
  let meta = '';
  let dataX = '';
  let inputVal = '';
  if (position === 'title') {
    title = p;
  } else if (position === 'h1') {
    h1 = p;
  } else if (position === 'meta') {
    meta = p.replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  } else if (position === 'dataAttr') {
    dataX = p.replace(/"/g, '&quot;');
  } else if (position === 'inputValue') {
    inputVal = p.replace(/"/g, '&quot;');
  }
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<title>${title}</title>
<meta name="description" content="${meta}"/>
</head><body>
<h1>${h1}</h1>
<div data-test="xss" data-x="${dataX}"></div>
<input data-test="xss" type="text" value="${inputVal}"/>
</body></html>`;
}

/**
 * Minimal page for hash-based XSS (payload only in URL fragment).
 * @returns {string}
 */
function buildBlankHtml() {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><title>blank</title></head><body></body></html>`;
}

/**
 * Start a local HTTP server on an ephemeral port for harness pages and canaries.
 * Also starts a second server on another port (different origin) for CORS-proxy probes without public internet.
 * @returns {Promise<{ baseUrl: string, crossOriginProbeUrl: string, server: import('http').Server, crossServer: import('http').Server, getCanaryHits: () => number, getCanaryJsHits: () => number, resetCanaries: () => void, close: () => Promise<void> }>}
 */
function createTestServer() {
  let canaryHits = 0;
  let canaryJsHits = 0;

  /** @type {import('http').Server} */
  const server = http.createServer((req, res) => {
    try {
      const host = req.headers.host || '127.0.0.1';
      const u = new URL(req.url || '/', `http://${host}`);
      const path = u.pathname;

      if (path === '/canary') {
        canaryHits += 1;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('ok');
        return;
      }
      if (path === '/canary.js') {
        canaryJsHits += 1;
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8' });
        res.end('globalThis.__bg_injected = true;\n');
        return;
      }
      if (path === '/blank') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildBlankHtml());
        return;
      }
      if (path === '/xss') {
        const pos = u.searchParams.get('pos') || 'title';
        const b64 = u.searchParams.get('p') || '';
        const payload = decodePayload(b64);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildXssHtml(pos, payload));
        return;
      }
      res.writeHead(404);
      res.end('not found');
    } catch (err) {
      res.writeHead(500);
      res.end(String(err));
    }
  });

  /** @type {import('http').Server} */
  const crossServer = http.createServer((req, res) => {
    try {
      const u = new URL(req.url || '/', 'http://127.0.0.1');
      if (u.pathname === '/probe') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(CORS_PROBE_BODY);
        return;
      }
      res.writeHead(404);
      res.end('not found');
    } catch (err) {
      res.writeHead(500);
      res.end(String(err));
    }
  });

  /** @type {Set<import('net').Socket>} */
  const serverSockets = new Set();
  /** @type {Set<import('net').Socket>} */
  const crossSockets = new Set();

  server.on('connection', (sock) => {
    serverSockets.add(sock);
    sock.on('close', () => serverSockets.delete(sock));
  });
  crossServer.on('connection', (sock) => {
    crossSockets.add(sock);
    sock.on('close', () => crossSockets.delete(sock));
  });

  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('invalid primary server address'));
        return;
      }
      crossServer.listen(0, '127.0.0.1', () => {
        const addr2 = crossServer.address();
        if (!addr2 || typeof addr2 === 'string') {
          server.close();
          reject(new Error('invalid cross-origin server address'));
          return;
        }
        resolve({
          baseUrl: `http://127.0.0.1:${addr.port}`,
          crossOriginProbeUrl: `http://127.0.0.1:${addr2.port}/probe`,
          corsProbeMarker: CORS_PROBE_BODY,
          server,
          crossServer,
          getCanaryHits: () => canaryHits,
          getCanaryJsHits: () => canaryJsHits,
          resetCanaries: () => {
            canaryHits = 0;
            canaryJsHits = 0;
          },
          close: () =>
            Promise.all([
              new Promise((res, rej) => {
                for (const s of serverSockets) {
                  try {
                    s.destroy();
                  } catch (_e) {}
                }
                server.close((e) => (e ? rej(e) : res()));
              }),
              new Promise((res, rej) => {
                for (const s of crossSockets) {
                  try {
                    s.destroy();
                  } catch (_e) {}
                }
                crossServer.close((e) => (e ? rej(e) : res()));
              }),
            ]).then(() => {}),
        });
      });
      crossServer.on('error', (e) => {
        server.close();
        reject(e);
      });
    });
    server.on('error', reject);
  });
}

module.exports = { createTestServer, decodePayload, buildXssHtml, CORS_PROBE_BODY };
