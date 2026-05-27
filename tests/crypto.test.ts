import { describe, it, expect } from 'vitest';
import {
  generateEcdhKeypair,
  importPeerPublicKey,
  deriveSessionKeys,
  encryptString,
  decryptString,
  signEnvelope,
  verifyEnvelope,
  generateSessionId,
} from '../src/core/crypto.js';
import {
  bytesToBase64url,
  base64urlToBytes,
} from '../src/core/encoding.js';

describe('encoding', () => {
  it('round-trips arbitrary bytes through base64url', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    const b64 = bytesToBase64url(bytes);
    expect(b64).not.toContain('+');
    expect(b64).not.toContain('/');
    expect(b64).not.toContain('=');
    const back = base64urlToBytes(b64);
    expect(Array.from(back)).toEqual(Array.from(bytes));
  });

  it('handles empty input', () => {
    expect(bytesToBase64url(new Uint8Array(0))).toBe('');
    expect(base64urlToBytes('').length).toBe(0);
  });
});

describe('ECDH key agreement', () => {
  it('derives the same keys on both sides', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();

    const aliceSeesBob = await importPeerPublicKey(bob.publicKeyB64);
    const bobSeesAlice = await importPeerPublicKey(alice.publicKeyB64);

    const aliceKeys = await deriveSessionKeys(alice.keyPair.privateKey, aliceSeesBob);
    const bobKeys = await deriveSessionKeys(bob.keyPair.privateKey, bobSeesAlice);

    // Verify the derived keys match by using Alice's AES key to encrypt and
    // Bob's AES key to decrypt.
    const message = 'hello envelope';
    const { nonceB64, ciphertextB64 } = await encryptString(aliceKeys.aesKey, message);
    const decrypted = await decryptString(bobKeys.aesKey, nonceB64, ciphertextB64);
    expect(decrypted).toBe(message);
  });
});

describe('AES-GCM encrypt/decrypt', () => {
  it('round-trips a string', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();
    const bobPub = await importPeerPublicKey(bob.publicKeyB64);
    const { aesKey } = await deriveSessionKeys(alice.keyPair.privateKey, bobPub);

    const msg = JSON.stringify({ users: [{ id: 1, name: 'Alice' }] });
    const { nonceB64, ciphertextB64 } = await encryptString(aesKey, msg);
    const out = await decryptString(aesKey, nonceB64, ciphertextB64);
    expect(out).toBe(msg);
  });

  it('uses a fresh nonce each time (ciphertexts differ for same plaintext)', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();
    const bobPub = await importPeerPublicKey(bob.publicKeyB64);
    const { aesKey } = await deriveSessionKeys(alice.keyPair.privateKey, bobPub);

    const a = await encryptString(aesKey, 'same message');
    const b = await encryptString(aesKey, 'same message');
    expect(a.nonceB64).not.toBe(b.nonceB64);
    expect(a.ciphertextB64).not.toBe(b.ciphertextB64);
  });

  it('throws on tampered ciphertext', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();
    const bobPub = await importPeerPublicKey(bob.publicKeyB64);
    const { aesKey } = await deriveSessionKeys(alice.keyPair.privateKey, bobPub);

    const { nonceB64, ciphertextB64 } = await encryptString(aesKey, 'hello');
    // Flip one character of the base64url ciphertext
    const tampered = ciphertextB64.slice(0, -1) + (ciphertextB64.endsWith('A') ? 'B' : 'A');
    await expect(decryptString(aesKey, nonceB64, tampered)).rejects.toThrow();
  });
});

describe('HMAC envelope signing', () => {
  it('verifies a valid signature', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();
    const bobPub = await importPeerPublicKey(bob.publicKeyB64);
    const { hmacKey } = await deriveSessionKeys(alice.keyPair.privateKey, bobPub);

    const sig = await signEnvelope(hmacKey, 1, 'sid123', 'nonce', 'ct');
    const ok = await verifyEnvelope(hmacKey, 1, 'sid123', 'nonce', 'ct', sig);
    expect(ok).toBe(true);
  });

  it('rejects a tampered signature', async () => {
    const alice = await generateEcdhKeypair();
    const bob = await generateEcdhKeypair();
    const bobPub = await importPeerPublicKey(bob.publicKeyB64);
    const { hmacKey } = await deriveSessionKeys(alice.keyPair.privateKey, bobPub);

    const sig = await signEnvelope(hmacKey, 1, 'sid123', 'nonce', 'ct');
    const ok = await verifyEnvelope(hmacKey, 1, 'sid123', 'nonce', 'ct-changed', sig);
    expect(ok).toBe(false);
  });
});

describe('session ID generation', () => {
  it('produces unique IDs', () => {
    const a = generateSessionId();
    const b = generateSessionId();
    expect(a).not.toBe(b);
    expect(a.length).toBeGreaterThan(10);
  });
});
