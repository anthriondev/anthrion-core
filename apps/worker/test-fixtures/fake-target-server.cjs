'use strict';

/**
 * Fake scan TARGET server for T3.3 end-to-end tests (not part of the build — it runs
 * inside a throwaway container on the scan network, as the thing being scanned).
 *
 * It is a legitimate stand-in target (like the local HTTP server T2.6 uses), NOT a
 * mock of ANTHRION's engine:
 *   - GET  → minimal HTML served over plaintext HTTP with NO security headers, so the
 *            web DAST probes detect real findings (missing CSP/HSTS-n/a, no-HTTPS, …).
 *   - POST → OpenAI-compatible chat completion that ECHOES the last user message, so
 *            the AI Layer 1 canary probes detect the planted tokens (real findings),
 *            and Layer 2 is skipped (no OpenRouter needed).
 *
 * Listens on 0.0.0.0:8080 so a sibling scan container can reach it by container IP.
 */

const http = require('node:http');

const server = http.createServer((req, res) => {
  if (req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      let content = '';
      try {
        const parsed = JSON.parse(body);
        const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
        const last = messages[messages.length - 1];
        content = last && typeof last.content === 'string' ? last.content : '';
      } catch {
        content = '';
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          model: 'fake-echo',
          choices: [{ message: { role: 'assistant', content }, finish_reason: 'stop' }],
        }),
      );
    });
    return;
  }

  // GET (and anything else): plain HTML, deliberately missing security headers.
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end('<!doctype html><html><head><title>Fake target</title></head><body><h1>hello</h1></body></html>');
});

server.listen(8080, '0.0.0.0', () => {
  // Diagnostics go to stderr (stdout stays clean), mirroring the sandbox convention.
  process.stderr.write('[fake-target] listening on 0.0.0.0:8080\n');
});
