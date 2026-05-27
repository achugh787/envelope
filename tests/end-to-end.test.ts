import { describe, it, expect } from 'vitest';
import { Guard } from '../src/server/index.js';
import { PROTOCOL_VERSION } from '../src/shared/constants.js';
import {
  generateEcdhKeypair,
  importPeerPublicKey,
  deriveSessionKeys,
} from '../src/core/crypto.js';
import {
  packEnvelope,
  unpackEnvelope,
  EnvelopeProtocolError,
} from '../src/core/envelope.js';
import { EnvelopeError } from '../src/shared/types.js';

describe('Guard end-to-end', () => {
  it('completes a full handshake + encrypted request/response cycle', async () => {
    const guard = new Guard();

    // ---- Client side: prepare handshake ----
    const clientEphemeral = await generateEcdhKeypair();

    // ---- Send to server ----
    const handshakeRes = await guard.handleHandshake({
      v: PROTOCOL_VERSION,
      clientPublicKey: clientEphemeral.publicKeyB64,
    });

    expect(handshakeRes.v).toBe(PROTOCOL_VERSION);
    expect(handshakeRes.sid).toBeTruthy();
    expect(handshakeRes.serverPublicKey).toBeTruthy();
    expect(handshakeRes.expiresAt).toBeGreaterThan(Date.now());

    // ---- Client side: derive its copy of the session keys ----
    const serverPub = await importPeerPublicKey(handshakeRes.serverPublicKey);
    const clientKeys = await deriveSessionKeys(
      clientEphemeral.keyPair.privateKey,
      serverPub
    );
    const clientSession = {
      sid: handshakeRes.sid,
      aesKey: clientKeys.aesKey,
      hmacKey: clientKeys.hmacKey,
      expiresAt: handshakeRes.expiresAt,
    };

    // ---- Client sends an encrypted request ----
    const reqPayload = JSON.stringify({ action: 'create', name: 'Alice' });
    const reqEnvelope = await packEnvelope(clientSession, reqPayload);

    // ---- Server decrypts ----
    const { plaintext, session: serverSession } = await guard.decryptRequest(reqEnvelope);
    expect(plaintext).toBe(reqPayload);

    // ---- Server encrypts a response ----
    const resPayload = JSON.stringify({ id: 1, name: 'Alice' });
    const resEnvelope = await guard.encryptResponse(serverSession, resPayload);

    // ---- Client decrypts the response ----
    const decryptedResponse = await unpackEnvelope(clientSession, resEnvelope);
    expect(decryptedResponse).toBe(resPayload);
  });

  it('rejects requests with unknown session ID', async () => {
    const guard = new Guard();
    const fakeEnvelope = {
      v: PROTOCOL_VERSION,
      sid: 'definitely-not-a-real-session',
      n: 'a',
      ct: 'a',
      sig: 'a',
    };
    await expect(guard.decryptRequest(fakeEnvelope)).rejects.toMatchObject({
      code: EnvelopeError.UNKNOWN_SESSION,
    });
  });

  it('rejects requests with bad signature', async () => {
    const guard = new Guard();
    const clientEph = await generateEcdhKeypair();
    const hs = await guard.handleHandshake({
      v: PROTOCOL_VERSION,
      clientPublicKey: clientEph.publicKeyB64,
    });
    const serverPub = await importPeerPublicKey(hs.serverPublicKey);
    const clientKeys = await deriveSessionKeys(clientEph.keyPair.privateKey, serverPub);

    const env = await packEnvelope(
      {
        sid: hs.sid,
        aesKey: clientKeys.aesKey,
        hmacKey: clientKeys.hmacKey,
        expiresAt: hs.expiresAt,
      },
      'hello'
    );

    // Tamper with the signature
    const tampered = { ...env, sig: env.sig.slice(0, -1) + (env.sig.endsWith('A') ? 'B' : 'A') };

    await expect(guard.decryptRequest(tampered)).rejects.toBeInstanceOf(EnvelopeProtocolError);
  });

  it('rejects requests with wrong protocol version', async () => {
    const guard = new Guard();
    await expect(
      guard.handleHandshake({ v: 99 as 1, clientPublicKey: 'whatever' })
    ).rejects.toMatchObject({ code: EnvelopeError.BAD_VERSION });
  });

  it('expires old sessions', async () => {
    const guard = new Guard({ sessionTtlMs: 10 });
    const clientEph = await generateEcdhKeypair();
    const hs = await guard.handleHandshake({
      v: PROTOCOL_VERSION,
      clientPublicKey: clientEph.publicKeyB64,
    });
    expect(await guard.getSession(hs.sid)).not.toBeNull();
    await new Promise((r) => setTimeout(r, 30));
    expect(await guard.getSession(hs.sid)).toBeNull();
  });
});
