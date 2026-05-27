/**
 * Example server using @akshit/envelope.
 *
 * Run:
 *   npm install express @akshit/envelope
 *   node server.js
 *
 * Then run client.html in a browser, or curl the handshake endpoint.
 */

import express from 'express';
import { createGuard } from '@akshit/envelope/server/express';

const app = express();
app.use(express.json());

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
  console.log('Open client.html in a browser to test.');
});
