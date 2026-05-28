/**
 * Example server using envelop-letterbox.
 *
 * Run:
 *   npm install && npm run build   (in the repo root — builds the dist/ bundle)
 *   cd examples/server && npm link envelop-letterbox && npm install
 *   node server.js
 *
 * Then open http://localhost:3000 in a browser (client is served from here).
 */

import express from 'express';
import { createRequire } from 'module';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { createGuard } from 'envelop-letterbox/server/express';

const __dirname = dirname(fileURLToPath(import.meta.url));
const require   = createRequire(import.meta.url);

// Locate the built client bundle inside the installed package.
// Works whether the package is npm-linked (local dev) or installed from npm.
const pkgDistDir    = dirname(require.resolve('envelop-letterbox'));   // → …/dist/index.cjs
const clientBundle  = resolve(pkgDistDir, '../dist/client/index.js'); // → …/dist/client/index.js
const clientHtml    = resolve(__dirname, '../client/client.html');

const app = express();
app.use(express.json());

// Serve the built client JS bundle at a stable URL the browser can import.
app.get('/envelope-client.js', (_req, res) => {
  res.setHeader('Content-Type', 'application/javascript');
  res.sendFile(clientBundle);
});

// Serve the demo UI so client and server share the same origin (no CORS needed).
app.get('/', (_req, res) => res.sendFile(clientHtml));

// One line to enable envelope wrapping for all routes below it.
app.use(createGuard({
  skipPaths: ['/health'],          // health check stays plain
}));

// Routes are completely unchanged from a normal Express app.
app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/users', (_req, res) => {
  res.json({
    users: [
      { id: 1, name: 'Alice', email: 'alice@example.com' },
      { id: 2, name: 'Bob', email: 'bob@example.com' },
    ],
  });
});

app.post('/users', (req, res) => {
  // req.body has been transparently decrypted before reaching here.
  console.log('Server received (decrypted):', req.body);
  res.json({
    id: 3,
    ...req.body,
    createdAt: new Date().toISOString(),
  });
});

const port = 3000;
app.listen(port, () => {
  console.log(`Envelope example server listening on http://localhost:${port}`);
  console.log(`Open http://localhost:${port} in a browser to test.`);
});
