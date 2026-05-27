import type { Envelope, Session } from '../shared/types.js';
import { EnvelopeError } from '../shared/types.js';
import { PROTOCOL_VERSION } from '../shared/constants.js';
import {
  encryptString,
  decryptString,
  signEnvelope,
  verifyEnvelope,
} from './crypto.js';

/**
 * Take a plaintext string + session and produce an Envelope ready to send on the wire.
 */
export async function packEnvelope(
  session: Session,
  plaintext: string
): Promise<Envelope> {
  const { nonceB64, ciphertextB64 } = await encryptString(
    session.aesKey,
    plaintext
  );
  const sig = await signEnvelope(
    session.hmacKey,
    PROTOCOL_VERSION,
    session.sid,
    nonceB64,
    ciphertextB64
  );
  return {
    v: PROTOCOL_VERSION,
    sid: session.sid,
    n: nonceB64,
    ct: ciphertextB64,
    sig,
  };
}

/**
 * Take an Envelope from the wire and decrypt it, validating signature.
 * Throws a typed error on any validation failure so callers can branch.
 */
export async function unpackEnvelope(
  session: Session,
  envelope: Envelope
): Promise<string> {
  if (envelope.v !== PROTOCOL_VERSION) {
    throw new EnvelopeProtocolError(EnvelopeError.BAD_VERSION);
  }
  if (envelope.sid !== session.sid) {
    throw new EnvelopeProtocolError(EnvelopeError.UNKNOWN_SESSION);
  }
  const sigOk = await verifyEnvelope(
    session.hmacKey,
    envelope.v,
    envelope.sid,
    envelope.n,
    envelope.ct,
    envelope.sig
  );
  if (!sigOk) {
    throw new EnvelopeProtocolError(EnvelopeError.BAD_SIGNATURE);
  }
  try {
    return await decryptString(session.aesKey, envelope.n, envelope.ct);
  } catch {
    throw new EnvelopeProtocolError(EnvelopeError.DECRYPT_FAILED);
  }
}

/**
 * Lightweight runtime guard for envelope shape, used before trusting input.
 */
export function isEnvelope(value: unknown): value is Envelope {
  if (typeof value !== 'object' || value === null) return false;
  const e = value as Record<string, unknown>;
  return (
    typeof e.v === 'number' &&
    typeof e.sid === 'string' &&
    typeof e.n === 'string' &&
    typeof e.ct === 'string' &&
    typeof e.sig === 'string'
  );
}

/**
 * Typed error used for protocol-level failures.
 * Carries one of the EnvelopeError codes so callers can react appropriately
 * (e.g. re-handshake on UNKNOWN_SESSION).
 */
export class EnvelopeProtocolError extends Error {
  constructor(public readonly code: EnvelopeError) {
    super(code);
    this.name = 'EnvelopeProtocolError';
  }
}
