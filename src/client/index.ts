import type {
  Session,
  HandshakeRequest,
  HandshakeResponse,
  Envelope,
} from '../shared/types.js';
import { EnvelopeError } from '../shared/types.js';
import {
  PROTOCOL_VERSION,
  DEFAULT_HANDSHAKE_PATH,
  ENVELOPE_HEADER,
} from '../shared/constants.js';
import {
  generateEcdhKeypair,
  importPeerPublicKey,
  deriveSessionKeys,
} from '../core/crypto.js';
import {
  packEnvelope,
  unpackEnvelope,
  isEnvelope,
  EnvelopeProtocolError,
} from '../core/envelope.js';

export interface TransportOptions {
  /** Base URL of the server (e.g. "https://api.example.com"). */
  baseURL: string;
  /** Handshake endpoint path. Default: "/__envelope/handshake". */
  handshakeEndpoint?: string;
  /** Optional extra fetch options applied to every request. */
  fetchOptions?: RequestInit;
  /** Print verbose logs for debugging. Default: false. */
  debug?: boolean;
  /** Override the global fetch (useful for testing or non-browser runtimes). */
  fetch?: typeof fetch;
}

export interface Transport {
  get<T = unknown>(path: string, init?: RequestInit): Promise<T>;
  post<T = unknown>(path: string, body?: unknown, init?: RequestInit): Promise<T>;
  put<T = unknown>(path: string, body?: unknown, init?: RequestInit): Promise<T>;
  patch<T = unknown>(path: string, body?: unknown, init?: RequestInit): Promise<T>;
  delete<T = unknown>(path: string, init?: RequestInit): Promise<T>;
  request<T = unknown>(method: string, path: string, body?: unknown, init?: RequestInit): Promise<T>;
  /** Force a fresh handshake. Useful after explicit logout, or for testing. */
  rotateSession(): Promise<void>;
}

/**
 * Create a new client transport.
 *
 * @example
 *   const api = createTransport({ baseURL: 'https://api.example.com' });
 *   const users = await api.get('/users');
 */
export function createTransport(options: TransportOptions): Transport {
  const baseURL = options.baseURL.replace(/\/$/, '');
  const handshakePath = options.handshakeEndpoint ?? DEFAULT_HANDSHAKE_PATH;
  const debug = options.debug ?? false;
  const fetchImpl = options.fetch ?? fetch;

  let session: Session | null = null;
  /** Single in-flight handshake promise so concurrent requests share one. */
  let handshakeInFlight: Promise<Session> | null = null;

  const log = (...args: unknown[]) => {
    if (debug) console.log('[envelope]', ...args);
  };

  async function performHandshake(): Promise<Session> {
    log('starting handshake');

    const { keyPair, publicKeyB64 } = await generateEcdhKeypair();

    const req: HandshakeRequest = {
      v: PROTOCOL_VERSION,
      clientPublicKey: publicKeyB64,
    };

    const res = await fetchImpl(`${baseURL}${handshakePath}`, {
      ...options.fetchOptions,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(options.fetchOptions?.headers ?? {}),
      },
      body: JSON.stringify(req),
    });

    if (!res.ok) {
      throw new Error(
        `Envelope handshake failed: ${res.status} ${res.statusText}`
      );
    }

    const body = (await res.json()) as HandshakeResponse;
    if (body.v !== PROTOCOL_VERSION) {
      throw new Error(`Envelope: unsupported server protocol version ${body.v}`);
    }

    const serverPublic = await importPeerPublicKey(body.serverPublicKey);
    const { aesKey, hmacKey } = await deriveSessionKeys(
      keyPair.privateKey,
      serverPublic
    );

    const newSession: Session = {
      sid: body.sid,
      aesKey,
      hmacKey,
      expiresAt: body.expiresAt,
    };
    session = newSession;
    log('handshake complete, sid=', body.sid);
    return newSession;
  }

  async function ensureSession(): Promise<Session> {
    if (session && session.expiresAt > Date.now() + 5000) {
      return session;
    }
    // Deduplicate concurrent handshakes — if one is already running, wait for it.
    if (handshakeInFlight) {
      return handshakeInFlight;
    }
    handshakeInFlight = performHandshake().finally(() => {
      handshakeInFlight = null;
    });
    return handshakeInFlight;
  }

  async function doRequest<T>(
    method: string,
    path: string,
    body: unknown,
    init?: RequestInit,
    isRetry = false
  ): Promise<T> {
    const sess = await ensureSession();

    // Pack request body (if any) into envelope.
    const reqBodyPlain = body === undefined ? null : JSON.stringify(body);

    let envelopeBody: string | undefined;
    if (reqBodyPlain !== null) {
      const env = await packEnvelope(sess, reqBodyPlain);
      envelopeBody = JSON.stringify(env);
    }

    const url = `${baseURL}${path.startsWith('/') ? path : '/' + path}`;
    log(method, url);

    const res = await fetchImpl(url, {
      ...options.fetchOptions,
      ...init,
      method,
      headers: {
        'content-type': 'application/json',
        [ENVELOPE_HEADER]: sess.sid,
        ...(options.fetchOptions?.headers ?? {}),
        ...(init?.headers ?? {}),
      },
      body: envelopeBody,
    });

    // If server says our session is unknown / signature bad, re-handshake once and retry.
    if (res.status === 409 || res.status === 401) {
      const errBody = await res.clone().json().catch(() => null);
      const code = errBody && typeof errBody === 'object' ? (errBody as { error?: string }).error : null;
      if (
        !isRetry &&
        (code === EnvelopeError.UNKNOWN_SESSION ||
          code === EnvelopeError.BAD_SIGNATURE)
      ) {
        log('session rejected, re-handshaking');
        session = null;
        return doRequest<T>(method, path, body, init, true);
      }
    }

    if (!res.ok) {
      throw new Error(`Envelope request failed: ${res.status} ${res.statusText}`);
    }

    // No content
    if (res.status === 204) return undefined as T;

    const respJson = await res.json();
    if (!isEnvelope(respJson)) {
      // Server returned plain JSON (e.g. a route that opted out). Pass through.
      return respJson as T;
    }

    try {
      const plain = await unpackEnvelope(sess, respJson);
      return JSON.parse(plain) as T;
    } catch (err) {
      if (
        !isRetry &&
        err instanceof EnvelopeProtocolError &&
        (err.code === EnvelopeError.UNKNOWN_SESSION ||
          err.code === EnvelopeError.BAD_SIGNATURE)
      ) {
        log('response decrypt failed, re-handshaking');
        session = null;
        return doRequest<T>(method, path, body, init, true);
      }
      throw err;
    }
  }

  return {
    get: (path, init) => doRequest('GET', path, undefined, init),
    post: (path, body, init) => doRequest('POST', path, body, init),
    put: (path, body, init) => doRequest('PUT', path, body, init),
    patch: (path, body, init) => doRequest('PATCH', path, body, init),
    delete: (path, init) => doRequest('DELETE', path, undefined, init),
    request: (method, path, body, init) => doRequest(method, path, body, init),
    rotateSession: async () => {
      session = null;
      await ensureSession();
    },
  };
}

// Re-export the envelope type for power users
export type { Envelope };
