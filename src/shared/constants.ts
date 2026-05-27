/** Current protocol version. */
export const PROTOCOL_VERSION = 1 as const;

/** Default handshake endpoint path. */
export const DEFAULT_HANDSHAKE_PATH = '/__envelope/handshake';

/** Default session TTL (1 hour). */
export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;

/** AES-GCM nonce length (bytes). */
export const NONCE_LENGTH = 12;

/** ECDH curve. */
export const ECDH_CURVE = 'P-256' as const;

/** AES key length in bits. */
export const AES_KEY_BITS = 256;

/** HMAC algorithm. */
export const HMAC_ALG = 'SHA-256' as const;

/** HTTP header used to signal an envelope-wrapped request. */
export const ENVELOPE_HEADER = 'x-envelope';
