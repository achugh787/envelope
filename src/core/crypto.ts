import { subtle, randomBytes } from './webcrypto.js';
import {
  bytesToBase64url,
  base64urlToBytes,
  stringToBytes,
  bytesToString,
  allocBytes,
} from './encoding.js';
import {
  ECDH_CURVE,
  AES_KEY_BITS,
  HMAC_ALG,
  NONCE_LENGTH,
} from '../shared/constants.js';

/**
 * Generate an ephemeral ECDH P-256 keypair.
 * Returns the keypair and its raw-encoded public key (base64url) ready to send.
 */
export async function generateEcdhKeypair(): Promise<{
  keyPair: CryptoKeyPair;
  publicKeyB64: string;
}> {
  const keyPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: ECDH_CURVE },
    false,
    ['deriveBits']
  );
  const rawPublic = await subtle.exportKey('raw', keyPair.publicKey);
  return {
    keyPair,
    publicKeyB64: bytesToBase64url(new Uint8Array(rawPublic)),
  };
}

/**
 * Import a peer's raw-encoded ECDH public key.
 */
export async function importPeerPublicKey(b64: string): Promise<CryptoKey> {
  const raw = base64urlToBytes(b64);
  return subtle.importKey(
    'raw',
    raw,
    { name: 'ECDH', namedCurve: ECDH_CURVE },
    false,
    []
  );
}

/**
 * Derive the symmetric AES-GCM key + HMAC key from our private key + peer's public key.
 * We use HKDF over the ECDH shared secret to derive two independent keys.
 */
export async function deriveSessionKeys(
  ownPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<{ aesKey: CryptoKey; hmacKey: CryptoKey }> {
  // Step 1: ECDH to get shared secret (256 bits)
  const sharedBits = await subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    ownPrivateKey,
    256
  );

  // Step 2: Import shared secret as HKDF base key
  const hkdfBase = await subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveKey']
  );

  // Step 3: Derive AES-GCM key from HKDF with info="aes"
  const aesKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: allocBytes(0),
      info: stringToBytes('envelope:aes:v1'),
    },
    hkdfBase,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );

  // Step 4: Derive HMAC key from HKDF with info="hmac"
  const hmacKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: allocBytes(0),
      info: stringToBytes('envelope:hmac:v1'),
    },
    hkdfBase,
    { name: 'HMAC', hash: HMAC_ALG, length: 256 },
    false,
    ['sign', 'verify']
  );

  return { aesKey, hmacKey };
}

/**
 * Encrypt a UTF-8 string with AES-GCM. Returns {nonce, ciphertext} both base64url.
 */
export async function encryptString(
  aesKey: CryptoKey,
  plaintext: string
): Promise<{ nonceB64: string; ciphertextB64: string }> {
  const nonce = randomBytes(NONCE_LENGTH);
  const ptBytes = stringToBytes(plaintext);
  const ctBuf = await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    ptBytes
  );
  return {
    nonceB64: bytesToBase64url(nonce),
    ciphertextB64: bytesToBase64url(new Uint8Array(ctBuf)),
  };
}

/**
 * Decrypt an AES-GCM ciphertext (base64url) with the given nonce (base64url).
 * Throws if authentication fails (tampering, wrong key).
 */
export async function decryptString(
  aesKey: CryptoKey,
  nonceB64: string,
  ciphertextB64: string
): Promise<string> {
  const nonce = base64urlToBytes(nonceB64);
  const ct = base64urlToBytes(ciphertextB64);
  const ptBuf = await subtle.decrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    ct
  );
  return bytesToString(new Uint8Array(ptBuf));
}

/**
 * Compute HMAC-SHA256 over the canonical envelope string and return base64url.
 * Canonical form: `${v}|${sid}|${n}|${ct}`.
 * (We sign over the parts rather than full JSON to avoid key-ordering issues.)
 */
export async function signEnvelope(
  hmacKey: CryptoKey,
  v: number,
  sid: string,
  nonceB64: string,
  ciphertextB64: string
): Promise<string> {
  const canonical = `${v}|${sid}|${nonceB64}|${ciphertextB64}`;
  const sig = await subtle.sign('HMAC', hmacKey, stringToBytes(canonical));
  return bytesToBase64url(new Uint8Array(sig));
}

/**
 * Verify the HMAC over an envelope. Returns true if valid.
 */
export async function verifyEnvelope(
  hmacKey: CryptoKey,
  v: number,
  sid: string,
  nonceB64: string,
  ciphertextB64: string,
  signatureB64: string
): Promise<boolean> {
  const canonical = `${v}|${sid}|${nonceB64}|${ciphertextB64}`;
  const sig = base64urlToBytes(signatureB64);
  return subtle.verify('HMAC', hmacKey, sig, stringToBytes(canonical));
}

/**
 * Generate a random session ID (16 bytes, base64url-encoded).
 */
export function generateSessionId(): string {
  return bytesToBase64url(randomBytes(16));
}
