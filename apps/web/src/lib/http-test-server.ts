import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

/**
 * Test-only helper: starts a real local HTTP server bound to an ephemeral port. The web
 * integration tests run the api client / SSE consumer against this — exercising the real
 * `fetch` + streaming + Zod path with real-shaped responses — instead of mocking the
 * units under test (CLAUDE.md §4). Not imported by application code, so it is never
 * bundled into the app.
 */

export interface TestServer {
  url: string;
  close: () => Promise<void>;
}

export type TestHandler = (req: IncomingMessage, res: ServerResponse) => void;

export async function startTestServer(handler: TestHandler): Promise<TestServer> {
  const server = createServer(handler);
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('Test server failed to bind to a port');
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections(); // drop open SSE connections so close() does not hang
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
}

/** Read a request body to a string (for asserting what the client sent). */
export function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += String(chunk);
    });
    req.on('end', () => {
      resolve(body);
    });
    req.on('error', reject);
  });
}

/** Format a value as a single SSE `data:` event (matches NestJS `@Sse` output). */
export function sseEvent(data: unknown): string {
  return `data: ${JSON.stringify(data)}\n\n`;
}
