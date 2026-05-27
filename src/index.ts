/**
 * Root entry point. The actual functionality is in the sub-exports:
 *   - @akshit/envelope/client       → createTransport
 *   - @akshit/envelope/server       → Guard (framework-agnostic)
 *   - @akshit/envelope/server/express → createGuard (Express middleware)
 *
 * This root export only re-exports shared types so users don't have to
 * import them from a deep path.
 */

export type {
  Envelope,
  Session,
  HandshakeRequest,
  HandshakeResponse,
} from './shared/types.js';

export { EnvelopeError } from './shared/types.js';
export { PROTOCOL_VERSION } from './shared/constants.js';
