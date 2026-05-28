/**
 * Universal access to the WebCrypto SubtleCrypto interface.
 * Works in browsers, Node 18+, Bun, Deno, and Cloudflare Workers.
 */

import { allocBytes, type Bytes } from './encoding.js';

function getCrypto(): Crypto {
  // Browser, Deno, Workers, modern Node — globalThis.crypto is standard.
  if (typeof globalThis !== 'undefined' && globalThis.crypto?.subtle) {
    return globalThis.crypto;
  }
  throw new Error(
    '@envelop/letterbox: WebCrypto is not available in this environment. ' +
    'Requires Node 18+ or a modern browser.'
  );
}

export const subtle: SubtleCrypto = getCrypto().subtle;

export function randomBytes(length: number): Bytes {
  const bytes = allocBytes(length);
  getCrypto().getRandomValues(bytes);
  return bytes;
}
