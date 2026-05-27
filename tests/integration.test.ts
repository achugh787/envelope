import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express from 'express';
import type { Server } from 'http';
import { createGuard } from '../src/server/adapters/express.js';
import { createTransport } from '../src/client/index.js';
import { isEnvelope } from '../src/core/envelope.js';

describe('Express + client integration', () => {
  let server: Server;
  let baseURL: string;
  let lastResponseBody: unknown = null;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use(createGuard());

    app.get('/users', (_req, res) => {
      res.json({ users: [{ id: 1, name: 'Alice' }] });
    });

    app.post('/echo', (req, res) => {
      res.json({ echoed: req.body });
    });

    await new Promise<void>((resolve) => {
      server = app.listen(0, () => resolve());
    });
    const address = server.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    baseURL = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('completes a full GET round-trip', async () => {
    const api = createTransport({ baseURL });
    const data = await api.get<{ users: { id: number; name: string }[] }>('/users');
    expect(data).toEqual({ users: [{ id: 1, name: 'Alice' }] });
  });

  it('completes a full POST round-trip with encrypted request body', async () => {
    const api = createTransport({ baseURL });
    const data = await api.post<{ echoed: { hello: string } }>('/echo', { hello: 'world' });
    expect(data).toEqual({ echoed: { hello: 'world' } });
  });

  it('what an observer would actually see on the wire is an envelope, not plaintext', async () => {
    // Use a wrapping fetch that captures the raw response text
    let capturedResponseText = '';
    const wrappingFetch: typeof fetch = async (input, init) => {
      const res = await fetch(input as RequestInfo, init);
      const text = await res.clone().text();
      // Capture only the non-handshake response
      if (!String(input).includes('handshake')) {
        capturedResponseText = text;
      }
      return res;
    };

    const api = createTransport({ baseURL, fetch: wrappingFetch });
    await api.get('/users');

    const parsed = JSON.parse(capturedResponseText);
    expect(isEnvelope(parsed)).toBe(true);
    // The ciphertext should not contain the word "Alice"
    expect(capturedResponseText).not.toContain('Alice');
    expect(capturedResponseText).not.toContain('users');
  });

  it('reuses a session across multiple requests (only one handshake)', async () => {
    let handshakeCount = 0;
    const countingFetch: typeof fetch = async (input, init) => {
      if (String(input).includes('handshake')) {
        handshakeCount++;
      }
      return fetch(input as RequestInfo, init);
    };

    const api = createTransport({ baseURL, fetch: countingFetch });
    await api.get('/users');
    await api.get('/users');
    await api.post('/echo', { x: 1 });
    expect(handshakeCount).toBe(1);
  });
});
