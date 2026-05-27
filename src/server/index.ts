import type {
  Session,
  HandshakeRequest,
  HandshakeResponse,
  Envelope,
} from '../shared/types.js';
import { EnvelopeError } from '../shared/types.js';
import {
  PROTOCOL_VERSION,
  DEFAULT_SESSION_TTL_MS,
} from '../shared/constants.js';
import {
  generateEcdhKeypair,
  importPeerPublicKey,
  deriveSessionKeys,
  generateSessionId,
} from '../core/crypto.js';
import {
  packEnvelope,
  unpackEnvelope,
  isEnvelope,
  EnvelopeProtocolError,
} from '../core/envelope.js';

export interface GuardOptions {
  /**
   * Session TTL in milliseconds. Default: 1 hour.
   * Shorter = more re-handshakes, fresher keys.
   * Longer = fewer handshakes, more exposure if a key is compromised.
   */
  sessionTtlMs?: number;
  /**
   * Custom session store. Default: in-memory Map.
   * For multi-instance servers, plug in Redis here.
   */
  sessionStore?: SessionStore;
}

/**
 * Pluggable session store. Default implementation is in-memory; for clustered
 * servers, provide a Redis-backed implementation.
 */
export interface SessionStore {
  get(sid: string): Promise<Session | null>;
  set(session: Session): Promise<void>;
  delete(sid: string): Promise<void>;
}

/** Default in-memory session store. Fine for single-instance servers. */
export class MemorySessionStore implements SessionStore {
  private store = new Map<string, Session>();

  async get(sid: string): Promise<Session | null> {
    const s = this.store.get(sid);
    if (!s) return null;
    if (s.expiresAt < Date.now()) {
      this.store.delete(sid);
      return null;
    }
    return s;
  }

  async set(session: Session): Promise<void> {
    this.store.set(session.sid, session);
  }

  async delete(sid: string): Promise<void> {
    this.store.delete(sid);
  }
}

/**
 * The framework-agnostic Guard. Holds session state and exposes two operations:
 *   - handleHandshake: perform an ECDH handshake and return the response
 *   - decryptRequest / encryptResponse: process individual request bodies
 *
 * Framework adapters (Express, etc.) wrap this in middleware.
 */
export class Guard {
  private store: SessionStore;
  private ttlMs: number;

  constructor(opts: GuardOptions = {}) {
    this.store = opts.sessionStore ?? new MemorySessionStore();
    this.ttlMs = opts.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  }

  /**
   * Process a handshake request. Generates server keypair, derives shared key,
   * stores the session, and returns the handshake response.
   */
  async handleHandshake(req: HandshakeRequest): Promise<HandshakeResponse> {
    if (req.v !== PROTOCOL_VERSION) {
      throw new EnvelopeProtocolError(EnvelopeError.BAD_VERSION);
    }
    if (typeof req.clientPublicKey !== 'string') {
      throw new EnvelopeProtocolError(EnvelopeError.MALFORMED);
    }

    const { keyPair, publicKeyB64 } = await generateEcdhKeypair();
    const clientPublic = await importPeerPublicKey(req.clientPublicKey);
    const { aesKey, hmacKey } = await deriveSessionKeys(
      keyPair.privateKey,
      clientPublic
    );

    const sid = generateSessionId();
    const expiresAt = Date.now() + this.ttlMs;
    await this.store.set({ sid, aesKey, hmacKey, expiresAt });

    return {
      v: PROTOCOL_VERSION,
      sid,
      serverPublicKey: publicKeyB64,
      expiresAt,
    };
  }

  /**
   * Decrypt an incoming envelope. Throws EnvelopeProtocolError with the
   * appropriate code on any failure — callers should map these to HTTP status.
   */
  async decryptRequest(envelope: Envelope): Promise<{
    plaintext: string;
    session: Session;
  }> {
    if (!isEnvelope(envelope)) {
      throw new EnvelopeProtocolError(EnvelopeError.MALFORMED);
    }
    const session = await this.store.get(envelope.sid);
    if (!session) {
      throw new EnvelopeProtocolError(EnvelopeError.UNKNOWN_SESSION);
    }
    const plaintext = await unpackEnvelope(session, envelope);
    return { plaintext, session };
  }

  /**
   * Encrypt an outgoing response for a known session.
   */
  async encryptResponse(session: Session, plaintext: string): Promise<Envelope> {
    return packEnvelope(session, plaintext);
  }

  /**
   * Look up a session by ID without decrypting anything (e.g. for responses
   * to GET requests that have no envelope body but still need the session key).
   */
  async getSession(sid: string): Promise<Session | null> {
    return this.store.get(sid);
  }
}

// Re-export types for adapter authors
export type { Session, HandshakeRequest, HandshakeResponse, Envelope };
export { EnvelopeProtocolError, EnvelopeError };
