/**
 * Root entry point. The actual functionality is in the sub-exports:
 *   - envelop-letterbox/client       → createTransport
 *   - envelop-letterbox/server       → Guard (framework-agnostic)
 *   - envelop-letterbox/server/express → createGuard (Express middleware)
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
