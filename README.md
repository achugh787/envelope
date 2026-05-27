# @akshit/envelope

Wrap your API requests and responses in encrypted envelopes. Replaces plaintext JSON in your network tab with opaque blobs.

```
┌─ DevTools Network tab ──────────────────────────────┐
│ Response:                                           │
│ { "v":1, "sid":"...", "n":"...", "ct":"...",        │
│   "sig":"..." }                                     │
│                                                     │
│ ← scrapers and curious users see this               │
└─────────────────────────────────────────────────────┘

         your app code sees this:
         { users: [{ id: 1, name: 'Alice' }, ...] }
```

## ⚠️ Read this first

**This is NOT end-to-end encryption against the end user.** Anyone with browser DevTools and a little patience can still see decrypted data — they can set a breakpoint inside the library and read the plaintext. There is no JavaScript library that can prevent this; it's a fundamental property of running code in a browser.

What this library *does* do:

- ✅ Make API responses opaque in the network tab
- ✅ Raise the cost of scraping APIs from "5 seconds with curl" to "you need to run my JavaScript"
- ✅ Deter casual inspection by users, support staff, and corporate proxies
- ✅ Prevent man-in-the-middle tampering (HMAC-signed envelopes)

What it does **not** do:

- ❌ Hide data from a determined user who opens DevTools
- ❌ Replace HTTPS (you still need it)
- ❌ Replace authentication or authorization
- ❌ Provide "security" in any cryptographic sense against the user

If you need real protection against the end user, that data should not be on the client at all.

## Install

```bash
npm install @akshit/envelope
```

## Quick start

### Server (Express)

```js
import express from 'express';
import { createGuard } from '@akshit/envelope/server/express';

const app = express();
app.use(express.json());
app.use(createGuard()); // <-- that's it

app.get('/users', (req, res) => {
  res.json({ users: [/* ... */] });   // automatically encrypted on the way out
});

app.listen(3000);
```

### Client (browser or Node)

```js
import { createTransport } from '@akshit/envelope/client';

const api = createTransport({ baseURL: 'http://localhost:3000' });

const data = await api.get('/users');
// data === { users: [...] }  ← decrypted transparently
```

Your route handlers and your UI code stay unchanged.

## How it works

1. **First request triggers an ECDH handshake.** The client and server each generate ephemeral P-256 keypairs and exchange public keys. Both sides derive the same AES-GCM key via HKDF over the ECDH shared secret. The key is never transmitted.

2. **Subsequent requests** are encrypted with AES-GCM and signed with HMAC-SHA256 (separate key, also derived from the same HKDF). The wire format is a small JSON envelope.

3. **Sessions expire** after a configurable TTL (default 1 hour). When the session is gone, the client re-handshakes automatically. Your app code doesn't see this.

4. **Server restarts** are handled gracefully: if the server doesn't recognize a session ID, it returns a 409 and the client re-handshakes once before retrying.

## Configuration

### `createTransport(options)`

| Option | Default | Description |
|---|---|---|
| `baseURL` | (required) | Base URL of the server |
| `handshakeEndpoint` | `/__envelope/handshake` | Path the server listens on for handshakes |
| `fetchOptions` | `{}` | Extra options applied to every fetch (credentials, headers, etc.) |
| `debug` | `false` | Log handshake + request events |
| `fetch` | global `fetch` | Custom fetch implementation |

Returns: `{ get, post, put, patch, delete, request, rotateSession }`.

### `createGuard(options)` (Express)

| Option | Default | Description |
|---|---|---|
| `handshakeEndpoint` | `/__envelope/handshake` | Path to handle handshakes on |
| `sessionTtlMs` | 3600000 (1h) | How long sessions live |
| `sessionStore` | in-memory `Map` | Implement `SessionStore` for Redis-backed multi-instance |
| `skipPaths` | `[]` | Strings or RegExps for paths to skip (e.g. `/health`) |

## Custom session store (multi-instance servers)

The default in-memory store is fine for single-instance servers. For clusters, plug in Redis:

```js
import { createGuard } from '@akshit/envelope/server/express';

class RedisSessionStore {
  async get(sid)        { /* fetch + deserialize from Redis */ }
  async set(session)    { /* serialize + store with TTL */ }
  async delete(sid)     { /* DEL */ }
}

app.use(createGuard({ sessionStore: new RedisSessionStore() }));
```

Note: `CryptoKey` is not serializable. You'll need to store the raw key bytes and re-import on read. A reference implementation will ship in a future release.

## Threat model in detail

| Attacker | Defended? | Notes |
|---|---|---|
| Casual user in DevTools → Network tab | ✅ Yes | Sees opaque envelope |
| Determined user setting breakpoints | ❌ No | Can read plaintext from variables |
| Scraper using curl / requests | ✅ Yes | Can't easily replay without doing ECDH |
| Scraper running headless browser | ⚠️ Partial | Has to actually execute your JS |
| MITM modifying responses in transit | ✅ Yes | HMAC will reject |
| MITM observing responses in transit | ✅ Yes (HTTPS + envelope) | But HTTPS alone is enough here |
| Browser extension reading window state | ❌ No | Extensions can read everything |
| Compromised CDN serving modified JS | ❌ No | Use SRI for your bundles |

## FAQ

**Q: Is this secure?**
A: It's not designed to be. It's designed to be *opaque*. Read the threat model above. If you're using it for real security against the user, you're using it wrong.

**Q: Why not just minify / obfuscate my JS?**
A: This isn't about hiding your code — it's about hiding the data shape and values flowing over the wire. Even with un-obfuscated JS, a scraper now has to *run* your code instead of just hitting your endpoint with curl.

**Q: Does it work in Node-to-Node?**
A: Yes. The client transport works in any environment with WebCrypto (Node 18+, Bun, Deno, browsers, Workers).

**Q: What about streaming responses (SSE, chunked)?**
A: Not supported in v0.1. Streams require a different protocol design. Use plain HTTPS for those endpoints.

**Q: What about file uploads?**
A: Multipart bodies are not envelope-wrapped in v0.1. The other fields go through normally.

**Q: I want some routes encrypted, others not.**
A: Use `skipPaths` in `createGuard`. The client transport sends a session header regardless; non-guarded routes ignore it.

**Q: Can I see the actual envelope for debugging?**
A: Yes, pass `debug: true` to `createTransport` for client-side logs. On the server, log inside your route handler.

## Roadmap

- Fastify, Hono, Next.js adapters
- Per-field encryption (encrypt only sensitive fields)
- Redis session store reference implementation
- Optional WASM-based crypto module (raises reverse-engineering cost)
- Streaming response support

## License

MIT
