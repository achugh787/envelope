import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { Guard, type GuardOptions } from '../index.js';
import { EnvelopeError } from '../../shared/types.js';
import { EnvelopeProtocolError } from '../../core/envelope.js';
import {
  DEFAULT_HANDSHAKE_PATH,
  ENVELOPE_HEADER,
} from '../../shared/constants.js';

export interface CreateGuardOptions extends GuardOptions {
  /** Handshake endpoint path. Default: "/__envelope/handshake". */
  handshakeEndpoint?: string;
  /**
   * Paths to skip envelope processing on (e.g. health checks, static files).
   * Default: none.
   */
  skipPaths?: (string | RegExp)[];
}

/**
 * Create Express middleware that:
 *   1. Handles the handshake endpoint
 *   2. Decrypts envelope-wrapped request bodies in place
 *   3. Encrypts JSON responses on the way out
 *
 * Mount it before your routes. Routes themselves are unchanged.
 *
 * @example
 *   app.use(express.json());
 *   app.use(createGuard());
 *   app.get('/users', (req, res) => res.json({ users: [...] }));
 */
export function createGuard(options: CreateGuardOptions = {}): RequestHandler {
  const guard = new Guard(options);
  const handshakePath = options.handshakeEndpoint ?? DEFAULT_HANDSHAKE_PATH;
  const skipPaths = options.skipPaths ?? [];

  function shouldSkip(path: string): boolean {
    return skipPaths.some((p) =>
      typeof p === 'string' ? path === p : p.test(path)
    );
  }

  return async function envelopeMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> {
    // Skip configured paths entirely
    if (shouldSkip(req.path)) {
      next();
      return;
    }

    // -------- Handshake endpoint --------
    if (req.path === handshakePath && req.method === 'POST') {
      try {
        const result = await guard.handleHandshake(req.body);
        res.status(200).json(result);
      } catch (err) {
        if (err instanceof EnvelopeProtocolError) {
          res.status(400).json({ error: err.code });
        } else {
          res.status(500).json({ error: 'envelope/handshake-failed' });
        }
      }
      return;
    }

    // -------- Determine session ID --------
    // We allow the SID either in the X-Envelope header (for GET/DELETE with no body)
    // or in the envelope's `sid` field (POST/PUT/PATCH with body).
    const headerSid = req.headers[ENVELOPE_HEADER];
    const bodySid =
      req.body && typeof req.body === 'object' ? (req.body as Envelope).sid : undefined;
    const sid = (Array.isArray(headerSid) ? headerSid[0] : headerSid) ?? bodySid;

    // If no SID at all, this request is not using envelope. Pass through unchanged.
    // (Useful during gradual migration — old clients can still call.)
    if (!sid) {
      next();
      return;
    }

    // -------- Decrypt request body if envelope-shaped --------
    let session;
    if (req.body && typeof req.body === 'object' && 'ct' in req.body) {
      try {
        const decrypted = await guard.decryptRequest(req.body as Envelope);
        session = decrypted.session;
        // Replace req.body with the decrypted JSON so downstream routes see plaintext
        try {
          req.body = JSON.parse(decrypted.plaintext);
        } catch {
          req.body = decrypted.plaintext;
        }
      } catch (err) {
        sendProtocolError(res, err);
        return;
      }
    } else {
      // No body to decrypt, but we still need the session for response encryption
      session = await guard.getSession(sid);
      if (!session) {
        res.status(409).json({ error: EnvelopeError.UNKNOWN_SESSION });
        return;
      }
    }

    // -------- Intercept res.json() to encrypt outgoing JSON --------
    const originalJson = res.json.bind(res);
    res.json = function (body: unknown): Response {
      // Fire and forget — but we have to await before actually sending.
      // Express's res.json is sync, so we trickily use a promise to send later.
      guard
        .encryptResponse(session!, JSON.stringify(body))
        .then((envelope) => {
          originalJson(envelope);
        })
        .catch((err) => {
          // If encryption fails, send a generic 500. Don't leak details.
          // eslint-disable-next-line no-console
          console.error('[envelope] response encryption failed:', err);
          res.status(500).end();
        });
      return res;
    };

    next();
  };
}

function sendProtocolError(res: Response, err: unknown): void {
  if (err instanceof EnvelopeProtocolError) {
    // Use 409 (Conflict) for session/signature issues so the client can retry
    // with a fresh handshake without confusing it with auth (401) or input (400).
    const status =
      err.code === EnvelopeError.UNKNOWN_SESSION ||
      err.code === EnvelopeError.BAD_SIGNATURE
        ? 409
        : 400;
    res.status(status).json({ error: err.code });
  } else {
    res.status(500).json({ error: 'envelope/internal-error' });
  }
}

// Type-only import to satisfy the body-sid check above
type Envelope = import('../../shared/types.js').Envelope;
