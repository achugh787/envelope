/**
 * base64url encoding / decoding.
 * Used everywhere in the wire format so envelopes are URL- and JSON-safe.
 */

/**
 * Uint8Array backed by a concrete ArrayBuffer (not SharedArrayBuffer).
 * WebCrypto types in newer TS require this distinction.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

/**
 * Allocate a fresh Uint8Array of the given length. Always ArrayBuffer-backed.
 */
export function allocBytes(length: number): Bytes {
  return new Uint8Array(new ArrayBuffer(length)) as Bytes;
}

export function bytesToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  // btoa exists in both modern Node (18+) and browsers
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64urlToBytes(b64url: string): Bytes {
  // Restore standard base64
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  // Pad
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = allocBytes(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function stringToBytes(str: string): Bytes {
  const encoded = new TextEncoder().encode(str);
  // TextEncoder returns Uint8Array<ArrayBufferLike>; copy into a concrete ArrayBuffer
  const out = allocBytes(encoded.length);
  out.set(encoded);
  return out;
}

export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
