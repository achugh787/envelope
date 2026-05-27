/**
 * The on-the-wire format for an encrypted request or response body.
 * This is what appears (opaquely) in the network tab.
 */
export interface Envelope {
  /** Protocol version. Bumped if wire format changes. */
  v: 1;
  /** Session ID (base64url). Identifies which session's key to use. */
  sid: string;
  /** Nonce / IV for AES-GCM (base64url, 12 bytes). */
  n: string;
  /** Ciphertext + GCM auth tag (base64url). */
  ct: string;
  /** HMAC-SHA256 signature over (v|sid|n|ct), base64url. */
  sig: string;
}

/**
 * The handshake request sent by the client to establish a session.
 */
export interface HandshakeRequest {
  v: 1;
  /** Client's ephemeral ECDH public key (base64url, raw P-256). */
  clientPublicKey: string;
}

/**
 * The handshake response from the server.
 */
export interface HandshakeResponse {
  v: 1;
  /** New session ID assigned by the server. */
  sid: string;
  /** Server's ephemeral ECDH public key (base64url, raw P-256). */
  serverPublicKey: string;
  /** When this session expires (unix ms). */
  expiresAt: number;
}

/**
 * An established session, held in memory on both client and server.
 * Contains the symmetric key derived via ECDH.
 */
export interface Session {
  sid: string;
  /** AES-GCM key, 32 bytes. */
  aesKey: CryptoKey;
  /** HMAC-SHA256 key, 32 bytes. */
  hmacKey: CryptoKey;
  expiresAt: number;
}

/**
 * Error codes returned by the server when a request can't be processed.
 * Client uses these to decide whether to re-handshake, fail, or retry.
 */
export enum EnvelopeError {
  /** Session ID is unknown or expired. Client should re-handshake. */
  UNKNOWN_SESSION = 'envelope/unknown-session',
  /** Envelope signature didn't verify. Client should re-handshake. */
  BAD_SIGNATURE = 'envelope/bad-signature',
  /** Envelope decryption failed. Likely tampered or corrupted. */
  DECRYPT_FAILED = 'envelope/decrypt-failed',
  /** Envelope version not supported. */
  BAD_VERSION = 'envelope/bad-version',
  /** Malformed envelope structure. */
  MALFORMED = 'envelope/malformed',
}
